# Protocol Cheat Sheet — DATUM Gateway ↔ Pool 

## Transport & framing

* **TCP**, non-blocking, epoll.
* Each frame = **4-byte header** (XOR-obfuscated) + **payload**.
* Payload may be:

  * **Sealed** to a public key (`crypto_box_seal`).
  * **Channel-encrypted** with per-session keypair + derived nonce.
  * **Optionally signed** (Ed25519, detached) — verified based on connection state.

### Header bit layout (little-endian `u32`, then XOR’d)

```
bits  0..21 : cmd_len            (22 bits; max ≈ 4 MiB)
bits 22..23 : reserved           (0)
bit      24 : is_signed          (1 = signature trailer present)
bit      25 : is_encrypted_pubkey (1 = sealed-to-pubkey)
bit      26 : is_encrypted_channel (1 = channel-encrypted)
bits 27..31 : proto_cmd          (5 bits; 0..31)
```

### Header XOR rolling keys

* Initial (client → server) **HELLO** header is XOR’d with constant **`0xDC871829`**.
* After HELLO, both sides evolve per header:

  * `key_next = header_xor_feedback(key_curr)` (Murmur3-style mixer).
* Key seeding from HELLO’s `nk` (see below):

  * **Client (after sending HELLO)**:

    * `sending_header_key  = feedback(nk)`
    * `receiving_header_key = feedback(~nk)`
  * **Server (after parsing HELLO)**:

    * `recv_key = feedback(nk)` (for next client header)
    * `send_key = feedback(~nk)` (for first server response)

### Nonce derivation (exact, 24 bytes, per direction; **not sent on wire**)

Let `nk` be the 4 random bytes inside HELLO, and `sess_pk_ed25519` the **client’s session Ed25519** public key.

```
nk' = (nk - 42) ^ U32LE(sess_pk_ed25519, offset=7)

for j in {0,4,8,12,16,20}:
    R = header_xor_feedback(nk' - 42)
    receiver_nonce[j..j+3] = LE32(R)
    sender_nonce  [j..j+3] = LE32(R ^ 0x57575757)
    nk' = ~R
```

Direction mapping:

* **Client** uses:

  * `receiver_nonce` to decrypt **server→client** channel messages,
  * `sender_nonce`   to encrypt **client→server** channel messages.
* **Server** uses:

  * `nonce_send = receiver_nonce`   (server→client),
  * `nonce_recv = sender_nonce`     (client→server).

Increment after **each** message you (en|de)crypt in that direction:

* Treat the 24-byte nonce as **six little-endian `u32` words**; add 1 to word 0; carry into later words only if overflow.

### Crypto & signatures — who signs what

| Message                            | Signed by            | Encrypted as                                       | Verified with…                          |
| ---------------------------------- | -------------------- | -------------------------------------------------- | --------------------------------------- |
| **HELLO** (proto=1, C→S)           | Client **long-term** | **Sealed** to pool **long-term X25519**            | Pool uses **client LT** verify key      |
| **HandshakeResp** (proto=2, S→C)   | Pool **long-term** ✅ | **Sealed** to **client session X25519**            | Client uses **pool LT** verify key      |
| **CONFIG** (cmd=5 / sub=0x99, S→C) | Pool **session** ✅   | **Channel-encrypted** (serverSessSK, clientSessPK) | Client uses **pool session** verify key |
| **All other cmd=5 payloads**       | usually unsigned     | Channel-encrypted as above                         | —                                       |

**Length semantics:** `cmd_len` is the **on-wire payload length** you’re sending:

* For **sealed** payloads, include `crypto_box_SEALBYTES`.
* For **channel** payloads, include `crypto_box_MACBYTES`.

### Top-level `proto_cmd` values

| `proto_cmd` | Direction | Meaning                                         |
| ----------- | --------- | ----------------------------------------------- |
| `1`         | C→S       | **HELLO** (handshake init; sealed+signed).      |
| `2`         | S→C       | **Handshake response** (sealed; **LT-signed**). |
| `5`         | both      | **Mining channel** (encrypted).                 |
| `7`         | S→C       | **INFO** (log string).                          |
| `1`         | S→C       | **PING** (stubbed).                             |

### Mining channel (`proto_cmd=5`) subcommands

**Server → Client**

* `0x99` **Client Configuration** (**must be signed** with server **session** key).
* `0x50` **Job validation** requests:

  * `0x10` **short-txn list** request,
  * `0x11` **txns by ID** request,
  * `0x12` **full tx set** request (excl. coinbase).
* `0x8F` **Share response** (accept/tentative/reject).
* `0xF9` **Blocknotify** (refresh template now).

**Client → Server**

* `0x10` **Coinbaser fetch** request.
* `0x27` **Share (POW) submit**.
* Replies to `0x50` above:

  * `0x50 0x90` **short-txn list** reply,
  * `0x50 0x91` **txns by ID** reply,
  * `0x50 0x92` **full tx set** reply.
