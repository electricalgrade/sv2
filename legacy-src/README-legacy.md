
# Stratum V2 mini-library for DATUM

This is a small, portable Stratum V2 (SV2) implementation packaged as a library and a couple of demo frontends. It’s designed to plug into **DATUM Gateway** so miners can speak SV2 while DATUM keeps its existing job/template pipeline.

* ✅ Works on Linux (epoll) and macOS/BSD (select() fallback)
* ✅ Clean encode/decode split, typed wrappers, adapter callbacks
* ✅ Demo client/server + adapter test harness
* ✅ Thin glue layer for DATUM: `datum_sv2.{h,c}`

---

## Features implemented (today)

**Wire / plumbing**

* Varint & string helpers; length-prefixed framed I/O
* `sv2_wire.{c,h}` low-level encode/decode
* Cross-platform event loop: epoll (Linux) → select() fallback

**Mining sub-protocol**

* `SetupConnection` → `SetupConnection.Success`
* `OpenStandardMiningChannel` → `…Success` (fixed 4-byte extranonce prefix `aabbccdd`)
* Server → miner: `SetTarget`, `NewMiningJob` (broadcast & per-channel)
* Miner → server: `SubmitSharesStandard` → `SubmitShares.Success/Error`
* Ack/Nack helpers

**Adapter library API**

* Start/stop a server, register callbacks:

  * `on_connect(fd)`, `on_disconnect(fd)`, `on_share(channel_id, job_id, nonce, ntime[4], version[4])`
* Push helpers:

  * `sv2_push_set_target(...)`
  * `sv2_broadcast_job(...)` / `sv2_push_new_job(...)`
* Share responses: `sv2_ack_share(...)`, `sv2_nack_share(...)`

**DATUM glue**

* `datum_sv2.{h,c}` bridges callbacks into DATUM:

  * Hooks you can implement/override:

    * `datum_on_connect`, `datum_on_disconnect`, `datum_validate_share`
  * Push helpers for DATUM → miners:

    * `datum_sv2_broadcast_job(...)`
    * `datum_sv2_set_target(...)`
* Minimal integration into `datum_stratum.c`: when a new V1 job is built, we compute a merkle root (using the subsidy-only coinbase and a fixed 12-byte extranonce) and broadcast a matching SV2 job to all SV2 miners.

---

## Roadmap / not yet implemented

* Noise handshake + AEAD encryption (required for Braiins/BOSminer in typical setups)
* Extended / group channels; full job control set (`SetNewPrevHash`, `SwitchToJob`, etc.)
* Full coinbase split/extranonce mgmt per channel; durable channel IDs
* Version-rolling negotiation in SV2 (SV1 currently handles v-roll)
* Auth/session resume, richer error codes, metrics

---

## Directory layout

```
src/
  sv2/
    sv2_wire.c        # low-level BOSS/varint/string helpers
    sv2_wire.h
    sv2_common.c      # message structs, encode/decode
    sv2_common.h
    sv2_mining.c      # mining protocol messages
    sv2_mining.h
    sv2_adapter.c     # server loop, callbacks, send helpers
    sv2_adapter.h
  sv2_client.c        # demo client
  sv2_server.c        # demo server
  datum_sv2.c         # DATUM glue (new)
  datum_sv2.h
```

---

## Build (standalone, with Makefile)

If you’re using the tiny Makefile you set up:

```bash
make clean && make
```

Artifacts go to `build/bin/` and `build/obj/`.

---

## Build (inside DATUM, CMake)

Add these to `CMakeLists.txt`:

```cmake
set(SV2_SRC
  src/sv2/sv2_wire.c
  src/sv2/sv2_common.c
  src/sv2/sv2_mining.c
  src/sv2/sv2_adapter.c
  src/datum_sv2.c
)
target_sources(datum_gateway PRIVATE ${SV2_SRC})
target_include_directories(datum_gateway PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/sv2)
find_package(Threads REQUIRED)
target_link_libraries(datum_gateway PRIVATE Threads::Threads)
```

Build DATUM as usual.

---

## Quick start (standalone demos)

One terminal (server):

```bash
./build/bin/sv2_server 3333
# or: ./build/bin/test_sv2_adapter 3333
```

Another terminal (client):

```bash
./build/bin/sv2_client 127.0.0.1 3333
```

Expected log:

```
client: sent SetupConnection
client: SetupConnection.Success used_version=2 flags=0x0
client: channel opened id=1
client: share accepted
```

Adapter test example:

```
[adapter-test] server up on 3333
[adapter-test] on_connect: fd=4 (channel_id=4)
[adapter-test] on_share: ch=4 job=42 nonce=1 ntime=00105e0f ver=00000020
[adapter-test] on_disconnect: fd=4
```

---

## Using the library in DATUM

1. **Start/stop the listener** (e.g., during gateway startup/shutdown):

```c
#include "datum_sv2.h"

static Sv2Handle *g_sv2 = NULL;

void start_sv2(void) {
    g_sv2 = datum_sv2_start("0.0.0.0", /*port*/3333);
}

void stop_sv2(void) {
    datum_sv2_stop(g_sv2);
}
```

2. **Broadcast jobs** whenever DATUM creates/updates a template:

```c
// Build merkle_root, pick version/ntime/nbits, choose job_id
datum_sv2_broadcast_job(job_id, merkle_root, version, ntime_le, nbits_le);
```

3. **Adjust difficulty/target** per channel:

```c
datum_sv2_set_target(channel_id, le_target);
```

4. **Handle miner events** by overriding the weak hooks:

```c
int datum_validate_share(uint32_t channel_id, uint32_t job_id, uint32_t nonce,
                         const uint8_t ntime[4], const uint8_t version[4]) {
    // Reuse your existing SV1 share validation primitives here.
    // Return 1 to accept, 0 to reject.
    return 1;
}

void datum_on_connect(uint32_t channel_id)   { /* track miner */ }
void datum_on_disconnect(uint32_t channel_id){ /* cleanup */     }
```

> Note: In the demo, `channel_id == fd`. If you later allocate your own persistent channel IDs, update the adapter to pass those into the callbacks.

---

## macOS / BSD

You’ll see a `select()` fallback (no `<sys/epoll.h>` on macOS). This is automatic; no code changes needed.

---

## Braiins OS / BOSminer compatibility

BOSminer (Braiins firmware) typically expects SV2 **with Noise/AEAD** and a pool **authority key** in the URL, e.g.:

```
stratum2+tcp://<POOL_IP>:3333/<AUTHORITY_PUBKEY_B58>
```

Your current demo runs **plaintext** SV2 (fine for local testing). To connect BOSminer in production, add:

* Noise NK/XK handshake + AEAD framing around your existing messages
* Pool authority key handling (secp256k1 keypair, publish base58-check pubkey)

Everything else (SetupConnection → OpenChannel → NewJob/SetTarget → SubmitShares) is already there.

---

## Common errors

* `fatal error: 'sys/epoll.h' file not found` (macOS)
  → You’re building the Linux path. The code already has a select() fallback; ensure the platform guard is picked up (or define `SV2_USE_SELECT`).

* Undefined functions like `atoi` in tests
  → Include the proper headers (e.g., `<stdlib.h>`).

* `No rule to make target build/obj/...`
  → Create `build/` directories (your Makefile has a rule now), or run `mkdir -p build/obj build/bin`.

---

## API reference (mini)

```c
// Start/stop
Sv2Server* sv2_server_start(const char* bind_ip, int port,
                            const Sv2Callbacks* cb, void* user);
void       sv2_server_stop(Sv2Server* s);

// Callbacks
typedef struct {
  void (*on_connect)(int fd, void* user);
  void (*on_disconnect)(int fd, void* user);
  void (*on_share)(uint32_t channel_id, uint32_t job_id, uint32_t nonce,
                   const uint8_t ntime[4], const uint8_t version[4], void* user);
} Sv2Callbacks;

// Pushes
int sv2_push_set_target(Sv2Server* s, uint32_t channel_id, uint32_t le_target);
int sv2_broadcast_job(Sv2Server* s, uint32_t job_id, const uint8_t merkle_root[32],
                      uint32_t version, uint32_t ntime_le, uint32_t nbits_le);

// Share responses
int sv2_ack_share(Sv2Server* s, uint32_t channel_id, uint32_t new_shares);
int sv2_nack_share(Sv2Server* s, uint32_t channel_id, uint32_t err_code,
                   const char* err_msg);
```

---

## License

MIT, same as DATUM. See headers for copyright.

---

## Changelog (short)

* v0.1: Basic Mining handshake, open standard channel, target/job push, share submit + ack/nack; adapter test; DATUM glue and job broadcast hook.
* Next: Noise/AEAD, authority key URL, extended channels, full job control, durable channel IDs, vardiff bridge.

