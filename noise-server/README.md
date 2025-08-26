

# SV2 Noise Handshake (XX/NX) + Minimal SetupConnection

This repo provides a tiny Stratum V2 “pool server” and a matching client that:

* perform a **Noise** handshake (default **XX**, optional **NX**),
* then exchange the **SV2 `SetupConnection` ↔ `SetupConnection.Success`** messages over the TCP socket (length-prefixed).

The code is intentionally small and dependency-light so we can iterate quickly and slot it into our larger SV2 work.

---

## Contents

```
src/
  sv2_pool_server.c      # server: Noise handshake + SV2 SetupConnection responder
  noise_client.c         # client: Noise handshake + SV2 SetupConnection initiator
  sv2_noise.c            # Noise wrapper (server+client helpers)
  sv2_noise.h
sv2_src/sv2/
  sv2_wire.c/.h          # tiny SV2 frame helpers (len-prefixed + frame builder/parser)
  sv2_common.c/.h        # minimal SetupConnection encode/decode
Makefile
```

---

## Prereqs

* **noise-c** (rweather/noise-c) installed, headers in `/usr/local/include/noise/protocol/` and libs in `/usr/local/lib`:

  * `libnoiseprotocol`, `libnoisekeys`, `libnoiseprotobufs`.
* A C11 compiler (clang/gcc).

> If the compiler complains `noise/protocol/noise.h` not found, either:
>
> * install noise-c (headers end up under `/usr/local/include/noise/protocol/`), or
> * tweak `INCLUDES` in the `Makefile` to point to your noise-c include path.

---

## Build

```bash
make clean && make -j
```

Produced binaries:

```
build/bin/sv2_pool_server
build/bin/noise_client
```

If you’re on Apple Silicon and worried about accidental x86 flags: this Makefile does **not** force `-m64` or cross-arch; it builds for your host arch (arm64 on M-series) by default.

---

## Run

### 1) Start the pool server (default **XX**)

```bash
build/bin/sv2_pool_server -l 0.0.0.0:3334 --prologue STRATUM/2
```

**Static key (optional):** pass a 32-byte secret as 64 hex chars to keep the same public key across runs:

```bash
SK=2ac661cc66f2c65a7246f10e804f7aa7cf704ca7af7eef62f5661e36af8aa6d8
build/bin/sv2_pool_server -l 0.0.0.0:3334 --prologue STRATUM/2 --sk "$SK"
```

You’ll see:

```
[pool] listening on 0.0.0.0:3334 (pattern=XX, prologue="STRATUM/2")
[pool] static pubkey: <32-byte hex>
```

### 2) Run the client

```bash
build/bin/noise_client -l 127.0.0.1:3334 --prologue STRATUM/2
```

On success you’ll see on the **server**:

```
[pool] handshake complete
[pool] SetupConnection: protocol=2 min=2 max=2 vendor="c-noise-client"
[pool] sent SetupConnection.Success (version=2 flags=0x00000000)
```

…and on the **client**:

```
[client] handshake complete
[client] SetupConnection.Success used_version=2 flags=0x00000000
```

---

## Patterns: XX and NX

* **XX** (default) works out-of-the-box with most noise-c builds.
* **NX** is implemented to match Stratum V2’s authenticated flow (responder has static key; initiator is ephemeral).

### Selecting NX

* **Server:** for now, use the `--nx` flag to select NX :

```bash
build/bin/sv2_pool_server -l 0.0.0.0:3334 --prologue STRATUM/2 --nx
```

* **Client:** pass `--nx` to select NX, or `--xx` to force XX:

```bash
build/bin/noise_client -l 127.0.0.1:3334 --prologue STRATUM/2 --nx
```

> Notes:
>
> * The code sets the responder’s static key for NX and generates an ephemeral local key for XX.
> * Some noise-c builds expose only certain hash/suite name variants (e.g., BLAKE2s vs SHA256). If you see “proto id fail”, rebuild noise-c with the suite you need or switch to the alternate suite string in code.

---

## CLI options

### Server (`sv2_pool_server`)

* `-l host:port` — bind address (default `0.0.0.0:3334`)
* `--prologue STR` — Noise prologue (default `"STRATUM/2"`)
* `--sk HEX64` — 32-byte static secret (hex). If omitted, a random secret is used.
* `--nx` — **select NX** pattern .

### Client (`noise_client`)

* `-l host:port` — server to connect (default `127.0.0.1:3334`)
* `--prologue STR` — must match server
* `--xx` — force XX
* `--nx` — select NX

---

## Expected framing (SV2)

* Transport: raw TCP with **length-prefixed** messages (`uint16_be length` + payload).
* `SetupConnection` and `SetupConnection.Success` are wrapped in a minimal SV2 frame (extension=COMMON) via `sv2_build_frame` / `sv2_parse_frame`.

This demo doesn’t yet encrypt transport frames with the post-split cipherstates — we keep it minimal and reliable for the handshake + SetupConnection flow first, then you can swap in `{sv2_noise_send_transport, sv2_noise_recv_transport}` where you write/read frames.

---

## Troubleshooting

* **`handshake failed rc=-3` / “read header failed”**
  Client and server are out of sync (pattern/prologue), or the peer closed the socket.
  Ensure both use the same **prologue** and **pattern** (XX vs NX), and that ports/firewalls allow the connection.

* **`server ctor rc=-9` or “proto id fail”**
  Your noise-c build doesn’t include that *suite name* (e.g., `Noise_XX_25519_ChaChaPoly_BLAKE2s`).
  Switch to the SHA256 variant in code or rebuild noise-c with that suite.

* **Static key seems to change every run**
  You didn’t pass `--sk`. Provide a 64-hex secret to keep the same public key.

* **Undefined symbols / headers not found**
  Make sure `-L/usr/local/lib` and `-I/usr/local/include` are present (they are in the Makefile), and that `libnoiseprotocol`, `libnoisekeys`, `libnoiseprotobufs` are installed.

* **macOS alignment warnings**
  We’ve removed unaligned casts (e.g., for short length fields) and use byte-wise assembly, so warnings should be gone. If you add your own framing, avoid unaligned pointer casts.

---

## What’s intentionally minimal

* Only the **SV2 SetupConnection** exchange is implemented post-handshake.
* No channel open / job dispatch yet.
* No persistent transport encryption wrappers are wired for the demo (they’re available in `sv2_noise.c` for the next step).

---


