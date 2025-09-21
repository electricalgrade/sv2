# server.py — DATUM Python pool (Box-based channel crypto)
import asyncio, struct
from typing import Tuple

from nacl import signing, public
from nacl.bindings import crypto_sign_BYTES

from protocol import (
    INITIAL_SENDING_HEADER_KEY, HEADER_SIZE,
    Header, pack_header, unpack_header, header_xor_feedback,
    derive_nonces_and_keys, increment_nonce,
    verify_detached,
    u32, u64,
)

import os
from nacl import signing, public

def load_or_create_ed25519(path: str) -> signing.SigningKey:
    if os.path.exists(path):
        with open(path, "rb") as f: return signing.SigningKey(f.read())
    sk = signing.SigningKey.generate()
    with open(path, "wb") as f: f.write(sk.encode())
    return sk

def load_or_create_x25519(path: str) -> public.PrivateKey:
    if os.path.exists(path):
        with open(path, "rb") as f: return public.PrivateKey(f.read())
    sk = public.PrivateKey.generate()
    with open(path, "wb") as f: f.write(bytes(sk))
    return sk

# ---- Pool long-term identity (what the gateway is configured with) ----
#POOL_LT_SIGN_SK = signing.SigningKey.generate()
#POOL_LT_SIGN_VK = POOL_LT_SIGN_SK.verify_key
#POOL_LT_ENC_SK  = public.PrivateKey.generate()
#POOL_LT_ENC_PK  = POOL_LT_ENC_SK.public_key
POOL_LT_SIGN_SK = load_or_create_ed25519("pool_lt_sign.sk")
POOL_LT_SIGN_VK = POOL_LT_SIGN_SK.verify_key
POOL_LT_ENC_SK  = load_or_create_x25519("pool_lt_enc.sk")
POOL_LT_ENC_PK  = POOL_LT_ENC_SK.public_key

def pool_pubkey_hex() -> str:
    # 32B Ed25519 pk || 32B X25519 pk  (128 hex chars)
    return (POOL_LT_SIGN_VK.encode() + POOL_LT_ENC_PK.encode()).hex()

class Connection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.r = reader
        self.w = writer
        self.peer = writer.get_extra_info('peername')

        # Rolling header XOR keys
        self.send_key = None   # server -> client (header obfuscation)
        self.recv_key = None   # client -> server (header obfuscation)

        # Session nonces (we mirror the gateway derivation exactly)
        self.nonce_send = None  # server -> client
        self.nonce_recv = None  # client -> server

        # Server session keys (fresh per connection)
        self.server_sess_sign_sk = signing.SigningKey.generate()
        self.server_sess_sign_vk = self.server_sess_sign_sk.verify_key
        self.server_sess_enc_sk  = public.PrivateKey.generate()
        self.server_sess_enc_pk  = self.server_sess_enc_sk.public_key

        # Client long-term / session pubkeys (filled at HELLO)
        self.client_lt_sign_vk   = None
        self.client_lt_enc_pk    = None
        self.client_sess_sign_vk = None
        self.client_sess_enc_pk  = None

        # High-level Box for channel crypto (server SK, client PK)
        self.box = None

        self.motd = b"Welcome to Python DATUM Prime (prototype)"

    async def read_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = await self.r.read(n - len(buf))
            if not chunk:
                raise ConnectionError("EOF")
            buf += chunk
        return buf

    async def send_frame(self, h: Header, payload: bytes):
        hdr, self.send_key = pack_header(h, self.send_key)
        self.w.write(hdr + payload)
        await self.w.drain()

    async def recv_frame(self) -> Tuple[Header, bytes]:
        hdr_bytes = await self.read_exact(HEADER_SIZE)
        h, self.recv_key = unpack_header(hdr_bytes, self.recv_key)
        payload = b""
        if h.cmd_len:
            payload = await self.read_exact(h.cmd_len)
        return h, payload

    async def handle(self):
        print(f"[+] Connection from {self.peer}")
        print("    Pool PUBKEY (paste into datum_gateway datum_pool_pubkey):")
        print(pool_pubkey_hex())

        # First client header is XOR'd with this constant
        self.recv_key = INITIAL_SENDING_HEADER_KEY

        # ---- (1) Receive HELLO (proto=1, sealed to pool long-term x25519) ----
        h, sealed = await self.recv_frame()
        if h.proto_cmd != 1:
            raise ValueError(f"Expected HELLO proto_cmd=1, got {h.proto_cmd}")

        hello = public.SealedBox(POOL_LT_ENC_SK).decrypt(sealed)

        # Parse fixed 4 pubkeys (128 bytes)
        i = 0
        if len(hello) < 128 + 1 + 4 + crypto_sign_BYTES:
            raise ValueError("HELLO too short")
        lt_pk_ed25519   = hello[i:i+32]; i += 32
        lt_pk_x25519    = hello[i:i+32]; i += 32
        sess_pk_ed25519 = hello[i:i+32]; i += 32
        sess_pk_x25519  = hello[i:i+32]; i += 32

        # Find 0xFE marker (after version string), then read nk (4 bytes)
        fe_pos = hello.find(b"\xFE", i)
        if fe_pos == -1 or fe_pos + 5 > len(hello):
            raise ValueError("HELLO malformed: 0xFE/nk not found")
        i = fe_pos + 1
        nk = struct.unpack_from("<I", hello, i)[0]
        i += 4

        # Verify detached signature over everything before the signature
        sig = hello[-crypto_sign_BYTES:]
        unsigned = hello[:-crypto_sign_BYTES]
        vk = signing.VerifyKey(lt_pk_ed25519)
        if not verify_detached(vk, unsigned, sig):
            raise ValueError("HELLO signature invalid")

        # Stash client keys
        self.client_lt_sign_vk   = vk
        self.client_lt_enc_pk    = public.PublicKey(lt_pk_x25519)
        self.client_sess_sign_vk = signing.VerifyKey(sess_pk_ed25519)
        self.client_sess_enc_pk  = public.PublicKey(sess_pk_x25519)

        # Derive rolling header keys for subsequent frames (must mirror gateway)
        self.recv_key = header_xor_feedback(nk)                 # for next client → server header
        self.send_key = header_xor_feedback(~nk & 0xFFFFFFFF)   # for this server → client header

        # Derive channel nonces (exactly like the gateway)
        server_sender, server_receiver = derive_nonces_and_keys(nk, sess_pk_ed25519)
        self.nonce_send = bytearray(server_sender)   # server → client
        self.nonce_recv = bytearray(server_receiver) # client → server

        # Create Box for channel crypto (server SK, client PK)
        self.box = public.Box(self.server_sess_enc_sk, self.client_sess_enc_pk)

        # ---- (2) Send Handshake Response (proto=2), sealed to client's SESSION pk; SIGNED with POOL LT ----
        resp = bytearray()
        resp += lt_pk_ed25519 + lt_pk_x25519
        resp += sess_pk_ed25519 + sess_pk_x25519
        resp += bytes(self.server_sess_sign_vk) + bytes(self.server_sess_enc_pk)
        resp += self.motd + b"\x00"

        sig2 = POOL_LT_SIGN_SK.sign(bytes(resp)).signature
        sealed_resp = public.SealedBox(self.client_sess_enc_pk).encrypt(bytes(resp) + sig2)
        h2 = Header(
            is_signed=True,
            is_encrypted_pubkey=True,
            is_encrypted_channel=False,
            proto_cmd=2,
            cmd_len=len(sealed_resp),
        )
        await self.send_frame(h2, sealed_resp)

        # ---- (3) Send CONFIG (cmd=5 / 0x99), SIGNED (server session key) then channel-encrypted ----
        cfg = bytearray()
        cfg += b"\x99"          # subcommand
        cfg += b"\x01"          # version
        payout = bytes.fromhex("6a24aa21a9ed")  # placeholder scriptsig (len<=255)
        cfg += bytes([len(payout)]) + payout
        cfg += u32(0xA1B2C3D4)  # prime_id
        tag = b"EGPOOL"
        cfg += bytes([len(tag)]) + tag
        cfg += u64(1 << 16)     # vardiff_min
        cfg += b"\x00\xFE"      # trailer
        cfg_sig = self.server_sess_sign_sk.sign(bytes(cfg)).signature  # signed by *server session* key

        # Encrypt with Box using explicit nonce; send only ciphertext (gateway manages nonce separately)
        ct = self.box.encrypt(bytes(cfg) + cfg_sig, bytes(self.nonce_send)).ciphertext
        increment_nonce(self.nonce_send)

        h5 = Header(is_signed=True, is_encrypted_channel=True, proto_cmd=5, cmd_len=len(ct))
        await self.send_frame(h5, ct)

        # ---- (4) Encrypted command loop (cmd=5) ----
        while True:
            h, payload = await self.recv_frame()
            if h.proto_cmd != 5:
                continue
            # Decrypt with Box using explicit nonce; payload is ciphertext only
            pt = self.box.decrypt(payload, bytes(self.nonce_recv))
            increment_nonce(self.nonce_recv)
            await self.handle_cmd5(pt)

    async def handle_cmd5(self, pt: bytes):
        if not pt:
            return
        sub = pt[0]; body = pt[1:]

        if sub == 0x27:  # Share submit
            job_id = body[0] if len(body) > 0 else 0
            target_byte = body[3] if len(body) > 3 else 0
            nonce = struct.unpack_from("<I", body, 8)[0] if len(body) >= 12 else 0

            # Minimal "accepted" echo back
            resp = bytearray()
            resp += b"\x8F"      # share response
            resp += b"\x01"      # ACCEPTED-ish (non-0x66)
            resp += b"\x00\x00"  # reason (u16)
            resp += bytes([target_byte])
            resp += bytes([job_id])
            resp += struct.pack("<I", nonce)
            await self.send_cmd5(resp)

        elif sub == 0x10:  # Coinbaser fetch request
            if len(body) < 8 + 32:
                return
            value = struct.unpack_from("<Q", body, 0)[0]
            # Return a tiny dummy blob (TODO: real coinbaser v2 blob)
            blob = b"\x00" * 32
            resp = bytearray()
            resp += b"\x11"                          # coinbaser response
            resp += struct.pack("<Q", value)         # echoed value
            resp += struct.pack("<I", len(blob))     # blob length
            resp += blob
            await self.send_cmd5(resp)

    async def send_cmd5(self, inner: bytes):
        ct = self.box.encrypt(bytes(inner), bytes(self.nonce_send)).ciphertext
        increment_nonce(self.nonce_send)
        h = Header(is_encrypted_channel=True, proto_cmd=5, cmd_len=len(ct))
        await self.send_frame(h, ct)

async def main(host="0.0.0.0", port=9333):
    print(f"[*] DATUM Python pool prototype on {host}:{port}")
    print("[*] Pool PUBKEY (paste into datum_gateway):")
    print(pool_pubkey_hex())

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        conn = Connection(reader, writer)
        try:
            await conn.handle()
        except Exception as e:
            print(f"[!] {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

    server = await asyncio.start_server(handler, host, port)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())

