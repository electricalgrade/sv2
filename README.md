# Stratum V2 Experiments

This repository contains experimental implementations of Stratum V2
components. This will be used for DATUM to support SV2 mining protocol. The main focus right now is a **Noise-based pool server and client**
(`noise-server/`) that perform:

- Noise XX/NX handshake
- SV2 `SetupConnection` ↔ `SetupConnection.Success`
- A minimal mining dispatcher (`OpenStandardMiningChannel`, `SubmitSharesStandard`, etc.)

---

## Layout

```

noise-server/     # current Noise handshake + SV2 mining dispatcher (active work)
legacy-src/       # archived pre-Noise implementation
pool\_server/      # mock ocean pool / helpers useful in end to end testing.
sv1\_to\_sv2\_bridge # SV1 → SV2 translation prototype
tests/            # test harnesses
doc/              # design notes, protocol references

```


### End-to-end test topology

```
+--------------------+        SV2 (mining)         +-------------------+        SV1            +--------------+
| pool_server        | <-------------------------> | DATUM SV2 mining  | <-------------------> | SV1 Miner(s) |
| (mock Ocean Pool)  |                             |  (bridge core)    |(sv2_to_sv1 Bridge)    |  (cgminer etc)
+--------------------+                             +-------------------+                       +--------------+
         ^                                                                                           ^
         |                                                                                           |
         +--------------------------------------- control / logs ------------------------------------+
```


### noise-server module layout

```
                                       (repo/noise-server)

                                  ┌──────────────────────────┐
                                  │        sv2_pool_server   │
                                  │  - TCP listen            │
                                  │  - Noise (XX/NX) hs      │
                                  │  - SetupConnection RX/TX │
                                  │  - hands off to mining   │
                                  └────────────┬─────────────┘
                                               │
                          SV2 frames (len-prefixed, then mining) │
                                               │
                           ┌───────────────────▼───────────────────┐
                           │         mining_dispatch               │
                           │  - reads frames after SetupSuccess    │
                           │  - routes mining msgs (open/submit)   │
                           │  - uses sv2_mining enc/dec + send     │
                           └───────────────────┬───────────────────┘
                                               │
                                               │ uses
                                               │
     ┌──────────────────────┐     ┌──────────────────────┐      ┌──────────────────────┐
     │  sv2_noise.{c,h}     │     │  sv2_wire.{c,h}      │      │  sv2_mining.{c,h}    │
     │  - Noise wrapper     │     │  - len-prefixed IO   │      │  - mining codecs     │
     │  - handshake + split │     │  - frame build/parse │      │  - helpers (send)    │
     └──────────────────────┘     └──────────────────────┘      └──────────────────────┘


Mock client (for local loop testing)
┌──────────────────────────┐
│      noise_client        │
│  - connects to server    │
│  - Noise handshake       │
│  - sends SetupConnection │
│  - (optional) mining msgs│
└──────────────────────────┘
```


---

## Getting started

The active implementation is in [`noise-server/`](noise-server/).  
See its [README.md](noise-server/README.md) for build instructions, usage, and TODOs.

---

## Status

- ✅ Noise XX/NX handshake working
- ✅ `SetupConnection` exchange implemented
- ✅ Minimal mining dispatcher integrated
- 🚧 Client mining messages (`OpenStandardMiningChannel`, `SubmitSharesStandard`) next
- 🚧 Datum bridge integration planned
- ⏳ Vardiff, accounting, and live miner tests pending
```




### Noise server local test setup (handshake → SV2 mining path)

```
+--------------------+                                        +-------------------+
| sv2_pool_server    |                                        | noise_client      |
| (server)           |                                        | (client)          |
|  - TCP listen      | <------------ TCP -------------------> |  - TCP connect    |
|  - Noise (XX/NX)   | <===== Noise secure channel ========>  |  - Noise (XX/NX)  |
|  - SetupConn RX/TX | <--- SV2 frames (len-prefixed) ----->  |  - SetupConn RX/TX|
|  - Mining dispatch | <------ SV2 Mining messages -------->  |  - (optional) mine|
+----------+---------+                                        +---------+---------+
           |                                                           |
           | uses                                                      | uses
           v                                                           v
   +-------------------+     +-------------------+             +-------------------+
   | sv2_wire.{c,h}    |     | sv2_noise.{c,h}  |             | sv2_wire.{c,h}    |
   | - frame build/    |     | - Noise hs/split |             | - frame build/    |
   |   parse + len IO  |     | - (option: xport)|             |   parse + len IO  |
   +-------------------+     +-------------------+             +-------------------+
           |
           | after SetupConnection.Success
           v
   +-----------------------+        uses         +-----------------------+
   | mining_dispatch.{c,h} | ------------------> | sv2_mining.{c,h}      |
   | - read post-setup     |                     | - mining codecs       |
   |   frames              |                     |   (open chan / jobs / |
   | - route mining msgs   |                     |    set target / submit|
   | - reply via sv2_wire  |                     |    shares / acks)     |
   +-----------------------+                     +-----------------------+
```

### Message/Layer timeline (one successful flow)

```
Client                                 Network / Noise                                Server
------                                 ------------------                              ------
TCP connect                      ->    TCP SYN/ACK                               ->    accept()
Noise handshake (XX/NX)          ->    e1 / e2 / split                          ->    Noise hs / split
SetupConnection (SV2 COMMON)     ->    [len][ext=0,msg=0x00][payload]           ->    parse → enc Success
SetupConnection.Success          <-    [len][ext=0,msg=0x01][payload]           <-    send Success
(OpenStandardMiningChannel)      ->    [len][ext=MINING,msg=0x10][payload]      ->    dispatcher: decode
OpenStandardMiningChannelSuccess <-    [len][ext=MINING,msg=0x11][payload]      <-    encode+send
NewMiningJob (future)            <-    [len][ext=MINING,msg=0x20][payload]      <-    encode+send
SetNewPrevHash (activate)        <-    [len][ext=MINING,msg=0x21][payload]      <-    encode+send
SubmitSharesStandard             ->    [len][ext=MINING,msg=0x30][payload]      ->    validate (stub)
SubmitSharesSuccess              <-    [len][ext=MINING,msg=0x31][payload]      <-    encode+send
```

### Quick legend

* **sv2\_pool\_server**: does TCP accept, **Noise** handshake, `SetupConnection`, then hands off to `mining_dispatch`.
* **mining\_dispatch**: reads **SV2 frames** after setup, routes to the right **sv2\_mining** codec / handler, sends replies via **sv2\_wire**.
* **sv2\_wire**: tiny SV2 frame builder/parser + 2-byte length-prefix I/O.
* **sv2\_noise**: Noise XX/NX wrapper (handshake + split; transport encrypt can be plugged in later).
* **sv2\_mining**: encode/decode for the minimal **Mining** subset (open standard channel, set target, new job, prevhash, submit shares, success/error).


