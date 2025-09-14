# DATUM Gateway ↔ Pool Protocol (Formal Spec, v0.4.0-beta)

> Scope: this document specifies the transport, framing, cryptography, state machine, and message formats used between a **DATUM Gateway** (client) and a **Pool** (server). It reflects the behavior implemented in `datum_gateway` v0.4.0-beta.

This spec uses **normative** “MUST/SHOULD/MAY” language.

---

## 1. Transport

* The transport is **TCP**. Either side MAY use non-blocking sockets and epoll/kqueue; this is out of scope for the wire spec.

* Every application frame on the wire is:

  ```
  Frame := XOR(Header32, rolling_key) || Payload[cmd_len]
  ```

* All multi-byte integers in payloads are **little-endian**.

* `cmd_len` MUST NOT exceed **2^22−1 = 4,194,303** bytes.

---

## 2. Header (32 bits, little-endian) — before XOR

```
bits  0..21  cmd_len              (22 bits)  // payload size on wire
bits 22..23  reserved             (MUST be 0)
bit      24  is_signed            (1 = signature trailer present in plaintext)
bit      25  is_encrypted_pubkey  (1 = payload is crypto_box_seal to a pubkey)
bit      26  is_encrypted_channel (1 = payload is channel-encrypted)
bits 27..31  proto_cmd            (5 bits; range 0..31)
```

**Constraints**

* Exactly **one** of `is_encrypted_pubkey` or `is_encrypted_channel` MUST be 1 for non-empty payloads.
* `proto_cmd` uses 5 bits; current assignments are in §6.

---

## 3. Header XOR Rolling Keys

To obfuscate headers, each 32-bit header word is XOR’d with a direction-local **rolling key**; after every header processed in that direction, the key is updated:

```
rolling_key_next = header_xor_feedback(rolling_key_current)
```

`header_xor_feedback(x)` is the 32-bit function implemented in the gateway (Murmur3-style mixer). Implementations MUST match its output exactly.

**Initial seeding**

* For the **client (gateway)**:

  * The **HELLO** header sent by the client MUST be XOR’d with the fixed constant `0xDC871829`.
  * After sending HELLO and deriving `nk` (see §5), the client MUST set:

    * `sending_header_key   = header_xor_feedback(nk)`
    * `receiving_header_key = header_xor_feedback(~nk)`

* For the **server (pool)**:

  * The very first header received from the client (HELLO) MUST be de-XOR’d with `0xDC871829`.
  * After parsing HELLO and extracting `nk`, the server MUST set:

    * `recv_key = header_xor_feedback(nk)`      // for next client→server header
    * `send_key = header_xor_feedback(~nk)`     // for the first server→client header

Thereafter each processed header advances the respective rolling key once.

---

## 4. Cryptographic Primitives

* **Key types**

  * **Signing:** Ed25519 (libsodium `crypto_sign_*`).
  * **Asymmetric encryption:** X25519 + XSalsa20-Poly1305 (libsodium `crypto_box_*`).

* **Sealed messages** (`is_encrypted_pubkey=1`):

  * Use `crypto_box_seal(recipient_pk, plaintext)` / `crypto_box_seal_open(...)`.
  * `cmd_len` MUST include `crypto_box_SEALBYTES`.

* **Channel-encrypted messages** (`is_encrypted_channel=1`):

  * A per-session shared key MUST be precomputed (`crypto_box_beforenm`).
  * Encrypt/Decrypt with `crypto_box_easy_afternm` / `crypto_box_open_easy_afternm` and an explicit **24-byte nonce** (see §5).
  * `cmd_len` MUST include `crypto_box_MACBYTES`.

* **Signatures**

  * Detached Ed25519 signatures (`crypto_sign_detached`) are appended to the **cleartext** (before any sealing/channel encryption) when `is_signed=1`.
  * Verification key depends on state (see §6.1, §6.2).

---

## 5. Session Keys, `nk`, and Nonce Derivation

### 5.1 Identities per side

* **Long-term (LT) identity**: Ed25519 + X25519.
* **Per-session identity** (generated each connection): Ed25519 + X25519.

### 5.2 `nk` (nonce/key seed)

* The client’s HELLO contains a random **`nk` (u32 LE)**. Both sides derive:

  * Header rolling-key seeds (see §3).
  * Two 24-byte nonces for channel encryption (one per direction).

### 5.3 Nonces (24 bytes, not transmitted)

Let `sess_pk_ed25519_client` be the **client’s session Ed25519 public key** (32 bytes).

Compute:

```
t  = (nk - 42) XOR U32LE(sess_pk_ed25519_client, offset=7)
for j in {0,4,8,12,16,20}:
    R = header_xor_feedback(t - 42)
    receiver_nonce[j..j+3] = LE32(R)
    sender_nonce  [j..j+3] = LE32(R ^ 0x57575757)
    t = ~R
```

**Direction mapping**

* **Client:**

  * uses `sender_nonce`   to encrypt client→server channel messages,
  * uses `receiver_nonce` to decrypt server→client channel messages.

* **Server:**

  * uses `nonce_recv = sender_nonce` to decrypt client→server,
  * uses `nonce_send = receiver_nonce` to encrypt server→client.

**Nonce increment**

After every (en|de)cryption in a given direction, increment that direction’s 24-byte nonce as **six little-endian u32 words**, with carry:

```
for j in {0,4,8,12,16,20}:
  w = LE32(nonce[j..j+3]) + 1
  write LE32(w) back
  if w != 0: break
```

---

## 6. Protocol Commands

### 6.1 Top-level `proto_cmd` values

| `proto_cmd` | Dir | Encryption                   | Signature (verifier)  | Meaning                                 |
| ----------- | --- | ---------------------------- | --------------------- | --------------------------------------- |
| `1`         | C→S | **Sealed** to pool LT        | **Client LT**         | **HELLO** (handshake init).             |
| `2`         | S→C | **Sealed** to client SESSION | **Pool LT**           | **Handshake response**.                 |
| `5`         | ↔   | **Channel**                  | optional (see subcmd) | **Mining channel** (subcommands below). |
| `7`         | S→C | none (plaintext)             | none                  | **INFO** (log string).                  |
| `1`         | S→C | channel/plain (TBD)          | none                  | **PING** (present; client stub).        |

**Verifier selection rule (client side):**

* If `datum_state < 2` (pre-handshake), verify with **Pool LT**.
* If `datum_state ≥ 2`, verify with **Pool SESSION**.

### 6.2 Mining channel (`proto_cmd=5`) subcommands

All cmd=5 payloads are **channel-encrypted** with the derived nonce scheme.

#### 6.2.1 Server → Client

* **`0x99` Client Configuration\`** (MUST be signed with **Pool SESSION** key)

  Plaintext:

  ```
  0x99
  0x01                                 // config version
  [scriptsig_len:u8] [scriptsig:≤255]  // pool payout scriptPubKey
  [prime_id:u32 LE]
  [tag_len:u8] [tag:bytes]             // ASCII tag
  [vardiff_min:u64 LE]                 // MUST be power-of-two; client rounds up if not
  0x00 0xFE
  + [sig:64] (Ed25519, Pool SESSION, over all bytes above)
  ```

* **`0x50` Job Validation Requests**

  * `0x10` **Short TXN list request**
    Request:

    ```
    0x50 0x10
    [job_id:u8]
    ```

    Reply (success):

    ```
    0x50 0x90
    [job_id:u8]
    0x01
    [txn_count:u16 LE]
    [ stxid:6 ] × txn_count         // SipHash48(txid, key); see note below
    [ xor_crosscheck:32 ]           // XOR of all txids; seed constant given in §6.4
    0xFE
    [pad: 1..~100 random]
    ```

    Reply (error):

    ```
    0x50 0x90
    [job_id|0xFF:u8]
    [err:u8]  // 0xF0/0xF1/0xF2/0xF3
    [pad...]
    ```

  * `0x11` **TXNs by ID request**
    Request:

    ```
    0x50 0x11
    [job_id:u8]
    [count:u16 LE]
    [ id:u16 LE ] × count
    ```

    Reply (success):

    ```
    0x50 0x91
    [job_id:u8]
    0x01
    [count:u16 LE]
    { [size_24bit:3] [raw_tx:size] } × count
    0xFE
    [pad: 1..~100 random]
    ```

    Reply (error): `0x50 0x91 [job_id:u8] [err:0xF0/0xF1/0xF4] [pad...]`

  * `0x12` **Full TX set request** (excludes coinbase)
    Request:

    ```
    0x50 0x12
    [job_id:u8]
    ```

    Reply (success):

    ```
    0x50 0x92
    [job_id:u8]
    0x01
    [txn_count:u16 LE]
    { [size_24bit:3] [raw_tx:size] } × txn_count
    0xFE
    // no pad (message may be large)
    ```

    Reply (error): `0x50 0x92 [job_id:u8] [err:0xF0/0xF1/0xF2] [pad...]`

* **`0x8F` Share Response**

  ```
  [status:u8]           // 0x50=ACCEPTED, 0x55=TENTATIVE, 0x66=REJECTED
  [reason:u16 LE]       // see §6.5
  [nonce:u32 LE]
  [target_pot:u8]
  [job_id:u8]
  ```

* **`0xF9` Blocknotify** (no body)

#### 6.2.2 Client → Server

* **`0x10` Coinbaser Fetch Request**

  ```
  0x10
  [value:u64 LE]
  [prevblockhash:32]
  0xFE
  [pad: 1..~80 random]
  ```

* **`0x27` POW / Share Submit**

  ```
  0x27
  [job_id:u8]
  [coinbase_id:u8]         // 0xFF if subsidy-only
  [flags:u8]               // bit0=is_block, bit1=subsidy_only, bit2=quickdiff
  [target_byte:u8]         // PoT byte used
  [ntime:u32 LE]
  [nonce:u32 LE]
  [version:u32 LE]
  [extranonce_len:u8]      // MUST be 12
  [extranonce:12]
  [username: ≤384 bytes, NUL-terminated]
  [reserved:4 zero bytes]

  // Optional one-time context if server lacks it:
  0x01
    [prevhash:32]
    [target_byte_index:u16 LE]
    [nbits:4]
    [datum_coinbaser_id:u8]
    [height:u32 LE]
    [coinbase_value:u64 LE]
    [txn_count:u32 LE]
    [txn_total_weight:u32 LE]
    [txn_total_size:u32 LE]
    [txn_total_sigops:u32 LE]
    [merkle_count:u8]
    [merklebranch:32] × merkle_count

  // Optional coinbase body (once per id or once if subsidy-only):
  0x02
    if subsidy-only:
      0xFF [coinb1_len:u16 LE] [coinb2_len:u16 LE] [coinb1] [coinb2]
    else:
      [coinbase_id:u8] [coinb1_len:u16 LE] [coinb2_len:u16 LE] [coinb1] [coinb2]

  0xFE
  [pad: 1..~80 random]
  ```

* **Replies to Job Validation** (as described under server requests).

---

## 6.3 HELLO / Handshake Response

### 6.3.1 HELLO (client → server) — `proto_cmd=1`, **sealed** to Pool LT, **signed** by Client LT

Cleartext (before sealing):

```
[ client_lt_pk_ed25519:32 ]
[ client_lt_pk_x25519:32 ]
[ client_sess_pk_ed25519:32 ]
[ client_sess_pk_x25519:32 ]
[ version_str_with_git_and_optional_tag, NUL ]
0xFE
[ nk:u32 LE ]
[ pad: 1..200 random bytes ]
[ sig:64 ]  // Ed25519, Client LT, over all bytes above
```

`cmd_len` = cleartext length + `crypto_box_SEALBYTES`.

### 6.3.2 Handshake Response (server → client) — `proto_cmd=2`, **sealed** to Client SESSION, **signed** by Pool LT

Cleartext:

```
[ echo client_lt_pk_ed25519:32 ]
[ echo client_lt_pk_x25519:32 ]
[ echo client_sess_pk_ed25519:32 ]
[ echo client_sess_pk_x25519:32 ]
[ server_sess_pk_ed25519:32 ]
[ server_sess_pk_x25519:32 ]
[ motd, NUL ]
[ sig:64 ]  // Ed25519, Pool LT, over all bytes above
```

`cmd_len` includes `crypto_box_SEALBYTES`.

---

## 6.4 Short-TXN ID (stxid) and Cross-check

* For `0x50/0x10` replies, each transaction ID (32 bytes) is mapped to a **48-bit stxid** using **SipHash** with a 16-byte key:

  ```
  siphash_key[0..15] = (client_lt_pk_ed25519[0..15] XOR pool_lt_pk_ed25519[0..15]) XOR 0x55
  stxid = SipHash_2_4(txid[0..31], siphash_key)  // take low 48 bits, little-endian
  ```

* The 32-byte cross-check is the XOR over all txids, initialized with the constant:

  ```
  A3 4F C1 9C 5E 88 76 12 0A 79 3E F1 6C 93 54 AF
  B8 1D E8 5A 20 C7 94 38 6F A1 02 D9 4A 7B F0 11
  ```

---

## 6.5 Share Response Status/Reasons

Status (`status:u8`):

* `0x50` ACCEPTED
* `0x55` ACCEPTED\_TENTATIVELY
* `0x66` REJECTED

Reason codes (`reason:u16 LE`) — subset:

```
10 BAD_JOB_ID              20 H_NOT_ZERO              28 MISSING_POOL_TAG
11 BAD_COINBASE_ID         21 HIGH_HASH               29 DUPLICATE_WORK
12 BAD_EXTRANONCE_SIZE     22 COINBASE_ID_MISMATCH    30 OTHER
13 BAD_TARGET              23 BAD_NTIME
14 BAD_USERNAME            24 BAD_VERSION
15 BAD_COINBASER_ID        25 STALE_BLOCK
16 BAD_MERKLE_COUNT        26 BAD_COINBASE
17 COINBASE_TOO_LARGE      27 BAD_COINBASE_OUTPUTS
18 COINBASE_MISSING
19 TARGET_MISMATCH
```

---

## 7. State Machine (Gateway perspective)

States:

* `0` — Start: send HELLO.
* `1` — Waiting for handshake response.
* `2` — Session established (keys/nonces set).
* `3` — Configured (after `0x99`), **mining ready**.

Timeouts (recommended):

* **Global inactivity**: if no server message for configured `datum_protocol_global_timeout_ms`, reconnect.
* **Share acceptance**: if shares are being sent but no acceptance for >30s, reconnect.

---

## 8. Limits & Constants

* `MAX_DATUM_PROTOCOL_JOBS` = **8** (job\_id range 0..7).
* `DATUM_PROTOCOL_MAX_CMD_DATA_SIZE` = **4,194,304** bytes (2^22); `cmd_len` MUST NOT exceed 2^22−1.
* `extranonce_len` MUST be **12**.
* Scripts (`scriptsig_len`, tags) MUST be ≤255 bytes.
* Random padding, where present, SHOULD be 1..\~100 bytes (or omitted in large messages as specified).

---

## 9. Validation & Error Handling (normative)

* If a message has `is_signed=1`, the signature verification MUST occur **after decryption** (if any) and MUST cover the entire plaintext portion preceding the signature.
* During handshake:

  * Server MUST verify HELLO signature with **Client LT** key.
  * Client MUST verify Handshake Response signature with **Pool LT** key.
* After handshake (`datum_state ≥ 2`), the client MUST verify signed server messages (e.g., CONFIG) with the **Pool SESSION** key.
* Channel nonces MUST remain in lockstep per direction; decryption MUST fail if MAC invalid.
* Unknown `proto_cmd` or subcommands SHOULD be logged and ignored.

---

## 10. Security Considerations

* Header XOR provides **obfuscation**, not secrecy; payloads MUST be properly sealed or channel-encrypted.
* Keys and nonces MUST be derived exactly per §3 and §5 to prevent reuse.
* Signed control paths (handshake, CONFIG) MUST remain signed with the correct keys (LT vs SESSION).
* Implementations SHOULD enforce size bounds and rate limits on large messages (e.g., full TX sets).

---

## 11. Interoperability Notes

* The gateway expects `vardiff_min` to be a power of two; it will round up if not.
* The pool’s payout “scriptsig” field is used as a **scriptPubKey** for payouts.
* On first POW submit per job/coinbase id, the gateway MAY include one-time context (`0x01`) and coinbase body (`0x02`) if the server has not yet seen them.

---

## 12. Message Registry (summary)

Top-level:

```
1  : HELLO (sealed, signed)
2  : Handshake Response (sealed, LT-signed)
5  : Mining Channel (channel-encrypted)
7  : INFO (plaintext)
```

Mining channel subcommands:

```
S→C: 0x99  Client Configuration (SESSION-signed)
S→C: 0x50  Job Validation:
       0x10 request → C→S reply 0x90
       0x11 request → C→S reply 0x91
       0x12 request → C→S reply 0x92
S→C: 0x8F  Share Response
S→C: 0xF9  Blocknotify

C→S: 0x10  Coinbaser Fetch
C→S: 0x27  POW Submit
C→S: 0x50  Job Validation Replies (0x90/0x91/0x92)
```

---

## 13. Conformance Checklist (Pool implementation)

* [ ] Parse/de-XOR header with correct rolling key; advance after each header.
* [ ] Decrypt sealed payloads to LT X25519 (HELLO), and to Client SESSION X25519 (Handshake Resp).
* [ ] Verify HELLO signature with Client LT; sign Handshake Resp with Pool LT.
* [ ] Derive `nk`, seed header keys, derive both nonces; maintain per-direction increments.
* [ ] Channel-encrypt cmd=5 payloads with `(PoolSessSK, ClientSessPK)` and `nonce_send`.
* [ ] For signed cmd=5 (CONFIG), sign plaintext with Pool SESSION key, then encrypt.
* [ ] Implement subcommands at minimum: send CONFIG `0x99`, reply to POW `0x27` with `0x8F`.
* [ ] Optional: job validation family `0x50` and coinbaser `0x10/0x11`.

---


