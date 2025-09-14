# Detailed Technical Article 

## Lifecycle from client start

1. **Init**

   * libsodium init; generate client long-term (Ed25519/X25519).
   * Load pool **long-term** pubkeys from config (`datum_pool_pubkey`, 128 hex).
   * Reset per-job flags; prep share queue.

2. **Connect**

   * TCP non-blocking, set `epoll`.
   * Set header obfuscation keys: `sending_header_key=0xDC871829`, `receiving_header_key=0`.
   * `datum_state=0`.

3. **HELLO (proto=1, C→S)**

   * Generate **session** keypair (Ed25519/X25519).
   * Build payload:

     * client LT pk\_ed25519 (32), pk\_x25519 (32),
     * client session pk\_ed25519 (32), pk\_x25519 (32),
     * version string + git (+ optional tag) **NUL-terminated**,
     * `0xFE`,
     * `nk:u32`,
     * random pad,
     * **signature:64** (Ed25519 with **client LT**), over everything before signature.
   * **Seal** to pool LT X25519 and send.
   * Seed header rolling keys & derive **both nonces** (per algorithm above).
   * `datum_state → 1`.

4. **Handshake Response (proto=2, S→C)**

   * Server parses HELLO, verifies signature, derives keys/nonces.
   * Server sends **sealed** (to client session X25519) payload, **signed with pool LT**:

     * echoes client LT/session PKs,
     * provides **server session** pk\_ed25519 + pk\_x25519,
     * MOTD (NUL-terminated).
   * Client verifies with pool **LT**, stores server session keys, precomputes channel; `datum_state → 2`.

5. **CONFIG (cmd=5 / 0x99, S→C)**

   * Server builds cleartext, **signs with server session** key, channel-encrypts with `(serverSessSK, clientSessPK, nonce0)`, sends ciphertext only.
   * Client decrypts with `(clientSessSK, serverSessPK, nonce0)`, verifies **session** signature, applies:

     * payout scriptsig,
     * prime\_id,
     * coinbase tag,
     * vardiff\_min (rounds to pow2 if necessary).
   * `datum_state → 3` (mining ready).

6. **Steady state**

   * **Coinbaser**: client `0x10` → server `0x11` blob; gateway parses to create outputs.
   * **Shares**: clients enqueue Stratum POWs; gateway sends `0x27` (first time per job/id includes one-time template context and coinbase body); server replies `0x8F`.
   * **Job validation**: server can request short-txn list, by-id txns, or full set.
   * **Keepalive**: PING is stubbed; liveness from message flow + timeouts.

7. **Timeouts / reconnect**

   * If **no server messages** for `datum_protocol_global_timeout_ms`, reconnect.
   * If shares are submitted but **no acceptance** for >30s, reconnect.
   * On exit, free queue; notify template refresh; restart.

## Bandwidth & privacy stance

* Pool never provides a full template; gateway remains template-authoritative.
* Compact validation flow (stxids + xor crosscheck) is favored; full tx set is fallback.
* One-time per-job context (merkle branches, coinbase body) piggybacks on first share to avoid repeated cost.
* Padding and header obfuscation reduce DPI/fingerprinting.

## Error handling

* Share reject reasons (subset): see Appendix B.
* Job-validation replies carry one-byte error tails for invalid states (`0xF0..0xF4`).
* Mis-signed or mis-encrypted frames are dropped with explicit log lines.

---

# Appendix A — Byte layouts (exhaustive)

## A0) Header (4 bytes, little-endian, then XOR)

* Bits as listed in the cheat sheet.
* On the wire: `LE32(header_bits) XOR rolling_key`.

## A1) HELLO (proto=1, C→S) — **sealed** + **LT-signed**

Cleartext **before sealing** (and before the signature):

```
[ client_lt_pk_ed25519:32 ]
[ client_lt_pk_x25519:32 ]
[ client_sess_pk_ed25519:32 ]
[ client_sess_pk_x25519:32 ]
[ version_str_with_git_and_optional_tag, NUL ]
0xFE
[ nk:u32 LE ]
[ pad: 1..200 random bytes ]
[ sig:64 (Ed25519, client LT, over all previous bytes) ]
```

`cmd_len` = `len(sealed_payload)` = cleartext length + `crypto_box_SEALBYTES`.

## A2) Handshake Response (proto=2, S→C) — **sealed** + **LT-signed**

Cleartext:

```
[ echo client_lt_pk_ed25519:32 ]
[ echo client_lt_pk_x25519:32 ]
[ echo client_sess_pk_ed25519:32 ]
[ echo client_sess_pk_x25519:32 ]
[ server_sess_pk_ed25519:32 ]
[ server_sess_pk_x25519:32 ]
[ motd, NUL ]
[ sig:64 (Ed25519, pool LT, over all previous bytes) ]
```

Sealed to **client session** X25519. `cmd_len` includes seal overhead.

## A3) Mining channel (`proto=5`) encryption/signature trailers

* Payload is first **cleartext \[+ optional signature trailer]**, then **channel-encrypted** with:

  * **Server→Client**: `(serverSessSK, clientSessPK, nonce_send)`
  * **Client→Server**: `(clientSessSK, serverSessPK, nonce_recv)`
* `cmd_len` = `cleartext_len + (optional 64) + crypto_box_MACBYTES`.

## A4) CONFIG (S→C; `cmd=5`, sub=**`0x99`**)

Cleartext (then **+64-byte signature by server session key**, then encrypted):

```
0x99
0x01                                 # version
[scriptsig_len:u8] [scriptsig:..]    # ≤255
[prime_id:u32 LE]
[tag_len:u8] [tag:..]                # ASCII
[vardiff_min:u64 LE]
0x00 0xFE
```

## A5) Coinbaser — request/response

**Request (C→S; sub=**`0x10`**):**

```
0x10
[value:u64 LE]           # available coinbase value for this job
[prevblockhash:32]       # to disambiguate on splits/forks
0xFE
[pad: 1..~80 random]
```

**Response (S→C; sub=**`0x11`**):**

```
0x11
[value:u64 LE]           # must match request to pair them
[len:u32 LE]
[blob:len]               # coinbaser v2 blob (pool-specific encoding)
```

## A6) Job validation family — server requests, client replies

**Request: short-txn list (S→C; `0x50 0x10`)**

```
0x50 0x10
[job_id:u8]
```

**Reply: (`0x50 0x90`) success**

```
0x50 0x90
[job_id:u8]
0x01
[txn_count:u16 LE]
[ stxid:6 bytes ] × txn_count    # SipHash48(txid, key from ed25519 pks)
[xor_crosscheck:32]              # xor of all txids (fast cross-check)
0xFE
[pad: 1..~100 random]
```

**Reply: (`0x50 0x90`) error**

```
0x50 0x90
[job_id|0xFF:u8]   # 0xFF if job_id itself was invalid
0xF0 | 0xF1 | 0xF2 | 0xF3
[pad...]
```

**Request: txns by id (S→C; `0x50 0x11`)**

```
0x50 0x11
[job_id:u8]
[count:u16 LE]
[ id:u16 LE ] × count
```

**Reply: (`0x50 0x91`) success**

```
0x50 0x91
[job_id:u8]
0x01
[count:u16 LE]
{ [size_24bit:3] [raw_tx:size] } × count
0xFE
[pad: 1..~100 random]
```

**Reply: (`0x50 0x91`) error**

```
0x50 0x91
[job_id:u8]
0xF0 | 0xF1 | 0xF4
[pad...]
```

**Request: full tx set (S→C; `0x50 0x12`)**

```
0x50 0x12
[job_id:u8]
```

**Reply: (`0x50 0x92`) success**

```
0x50 0x92
[job_id:u8]
0x01
[txn_count:u16 LE]
{ [size_24bit:3] [raw_tx:size] } × txn_count
0xFE
# (no random pad; message may be large)
```

**Reply: (`0x50 0x92`) error**

```
0x50 0x92
[job_id:u8]
0xF0 | 0xF1 | 0xF2
[pad...]
```

## A7) Share submit — client → server (sub=**`0x27`**)

```
0x27
[job_id:u8]
[coinbase_id:u8]          # 0xFF if subsidy-only
[flags:u8]                # bit0=is_block, bit1=subsidy_only, bit2=quickdiff
[target_byte:u8]          # byte of PoT target used
[ntime:u32 LE]
[nonce:u32 LE]
[version:u32 LE]
[extranonce_len:u8]       # fixed 12
[extranonce:12]
[username: <=384 bytes, NUL-terminated]
[reserved:4 zero bytes]

# Optional one-time job context (first submit for this job/coinbase id):
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

# Optional coinbase body (once per id or once for subsidy-only):
0x02
  if subsidy_only:
     0xFF [coinb1_len:u16 LE] [coinb2_len:u16 LE] [coinb1] [coinb2]
  else:
     [coinbase_id:u8] [coinb1_len:u16 LE] [coinb2_len:u16 LE] [coinb1] [coinb2]

0xFE
[pad: 1..~80 random]
```

## A8) Share response — server → client (sub=**`0x8F`**)

Exactly **9 bytes**:

```
[status:u8]                       # 0x50=ACCEPTED, 0x55=TENTATIVE, 0x66=REJECTED
[reason:u16 LE]                   # error code (see Appendix B); often 0 on accept
[nonce:u32 LE]                    # echoes submit nonce
[target_pot:u8]                   # “TargetPOT” index byte
[job_id:u8]
```

## A9) Blocknotify — server → client (sub=**`0xF9`**)

```
0xF9
# no body
```

## A10) INFO — server → client (`proto_cmd=7`)

```
[ ASCII bytes ... ]   # human-readable log line (NUL not required)
```

## A11) PING — server → client (`proto_cmd=1`)

* Present but client handler is a stub; body format not enforced yet.

---

# Appendix B — Share reject reason codes (subset)

From `datum_protocol.h`:

| Code | Name                                  |
| ---- | ------------------------------------- |
| 10   | `DATUM_REJECT_BAD_JOB_ID`             |
| 11   | `DATUM_REJECT_BAD_COINBASE_ID`        |
| 12   | `DATUM_REJECT_BAD_EXTRANONCE_SIZE`    |
| 13   | `DATUM_REJECT_BAD_TARGET`             |
| 14   | `DATUM_REJECT_BAD_USERNAME`           |
| 15   | `DATUM_REJECT_BAD_COINBASER_ID`       |
| 16   | `DATUM_REJECT_BAD_MERKLE_COUNT`       |
| 17   | `DATUM_REJECT_BAD_COINBASE_TOO_LARGE` |
| 18   | `DATUM_REJECT_COINBASE_MISSING`       |
| 19   | `DATUM_REJECT_TARGET_MISMATCH`        |
| 20   | `DATUM_REJECT_H_NOT_ZERO`             |
| 21   | `DATUM_REJECT_HIGH_HASH`              |
| 22   | `DATUM_REJECT_COINBASE_ID_MISMATCH`   |
| 23   | `DATUM_REJECT_BAD_NTIME`              |
| 24   | `DATUM_REJECT_BAD_VERSION`            |
| 25   | `DATUM_REJECT_STALE_BLOCK`            |
| 26   | `DATUM_REJECT_BAD_COINBASE`           |
| 27   | `DATUM_REJECT_BAD_COINBASE_OUTPUTS`   |
| 28   | `DATUM_REJECT_MISSING_POOL_TAG`       |
| 29   | `DATUM_REJECT_DUPLICATE_WORK`         |
| 30   | `DATUM_REJECT_OTHER`                  |

---

# Appendix C — Pseudocode (nonce & header key)

```c
// header feedback (matches code)
uint32_t datum_header_xor_feedback(uint32_t i);

// after sending HELLO:
client.sending_key   = feedback(nk);
client.receiving_key = feedback(~nk);

// server, after parsing HELLO:
server.recv_key = feedback(nk);
server.send_key = feedback(~nk);

// derive nonces
nk' = (nk - 42) ^ U32LE(client_session_pk_ed25519, 7);
for (j=0; j<24; j+=4) {
  R = feedback(nk' - 42);
  receiver_nonce[j..j+3] = LE32(R);
  sender_nonce  [j..j+3] = LE32(R ^ 0x57575757);
  nk' = ~R;
}

// increment nonce (little-endian 6x u32)
void increment_nonce(uint8_t nonce[24]){
  for (int j=0; j<24; j+=4) {
    uint32_t *w = (uint32_t*)&nonce[j];
    (*w)++;
    if (*w) break;
  }
}
```



