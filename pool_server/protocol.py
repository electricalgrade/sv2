# protocol.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple
import struct

from nacl import signing, public, bindings

INITIAL_SENDING_HEADER_KEY = 0xDC871829
HEADER_SIZE = 4
NONCE_SIZE = bindings.crypto_box_NONCEBYTES  # 24

# Header layout (LE u32):
# bits 0..21  : cmd_len (22)
# bits 22..23 : reserved
# bit  24     : is_signed
# bit  25     : is_encrypted_pubkey
# bit  26     : is_encrypted_channel
# bits 27..31 : proto_cmd (5)

def header_xor_feedback(i: int) -> int:
    s = 0xb10cfeed
    h = s
    k = i & 0xFFFFFFFF
    k = (k * 0xcc9e2d51) & 0xFFFFFFFF
    k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
    k = (k * 0x1b873593) & 0xFFFFFFFF
    h ^= k
    h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
    h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
    h ^= 4
    h ^= (h >> 16)
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= (h >> 16)
    return h & 0xFFFFFFFF

def xor_header(buf4: bytearray, key: int) -> None:
    (v,) = struct.unpack("<I", buf4)
    v ^= key & 0xFFFFFFFF
    buf4[:] = struct.pack("<I", v)

@dataclass
class Header:
    is_signed: bool = False
    is_encrypted_pubkey: bool = False
    is_encrypted_channel: bool = False
    proto_cmd: int = 0
    cmd_len: int = 0

def pack_header(h: Header, rolling_key: int) -> Tuple[bytes, int]:
    if h.cmd_len < 0 or h.cmd_len > 0x3FFFFF:  # 22 bits
        raise ValueError("cmd_len out of range")
    v = 0
    v |= (h.cmd_len & 0x3FFFFF)            # bits 0..21
    if h.is_signed:            v |= (1 << 24)
    if h.is_encrypted_pubkey:  v |= (1 << 25)
    if h.is_encrypted_channel: v |= (1 << 26)
    v |= ((h.proto_cmd & 0x1F) << 27)      # bits 27..31
    raw = bytearray(struct.pack("<I", v))
    xor_header(raw, rolling_key)
    next_key = header_xor_feedback(rolling_key)
    return bytes(raw), next_key

def unpack_header(buf: bytes, rolling_key: int) -> Tuple[Header, int]:
    if len(buf) != HEADER_SIZE:
        raise ValueError("Header size mismatch")
    raw = bytearray(buf)
    xor_header(raw, rolling_key)
    (v,) = struct.unpack("<I", raw)
    cmd_len = v & 0x3FFFFF
    is_signed            = bool((v >> 24) & 1)
    is_encrypted_pubkey  = bool((v >> 25) & 1)
    is_encrypted_channel = bool((v >> 26) & 1)
    proto_cmd            = (v >> 27) & 0x1F
    next_key = header_xor_feedback(rolling_key)
    return Header(is_signed, is_encrypted_pubkey, is_encrypted_channel, proto_cmd, cmd_len), next_key

def derive_nonces_and_keys(nk: int, client_session_pk_ed25519: bytes) -> tuple[bytes, bytes]:
    """
    Mirror the client's derivation exactly (datum_protocol.c):

        memset(session_nonce_receiver, 0, 24);
        nk -= 42;
        nk = nk ^ U32LE(session_pk_ed25519, 7);
        for j in 0..24 step 4:
            receiver[j] = header_xor_feedback(nk - 42);
            sender[j]   = receiver[j] ^ 0x57575757;
            nk = receiver[j];
            nk = ~nk;

    On the server:
      - server->client (send)   must use the client's *receiver* nonce (the 'base')
      - client->server (recv)   must use the client's *sender*   nonce (base ^ 0x57575757)
    """
    # Start from provided nk, apply the same pre-loop tweaks
    nk_local = (nk - 42) & 0xFFFFFFFF
    pkword   = struct.unpack_from("<I", client_session_pk_ed25519, 7)[0]
    nk_local = (nk_local ^ pkword) & 0xFFFFFFFF

    recv_base = bytearray(b"\x00" * NONCE_SIZE)   # this becomes client's receiver (our send)
    send_base = bytearray(b"\x00" * NONCE_SIZE)   # this becomes client's sender  (our recv)

    for j in range(0, NONCE_SIZE, 4):
        val = header_xor_feedback((nk_local - 42) & 0xFFFFFFFF)
        struct.pack_into("<I", recv_base, j, val)
        struct.pack_into("<I", send_base, j, val ^ 0x57575757)
        nk_local = (~val) & 0xFFFFFFFF

    server_sender  = bytes(recv_base)  # server -> client
    server_receiver= bytes(send_base)  # client -> server
    return server_sender, server_receiver

def increment_nonce(nonce: bytearray) -> None:
    # Increment little-endian 24-byte nonce in 32-bit words (like the C code)
    for i in range(0, NONCE_SIZE, 4):
        w, = struct.unpack_from("<I", nonce, i)
        w = (w + 1) & 0xFFFFFFFF
        struct.pack_into("<I", nonce, i, w)
        if w != 0:
            break

def u32(v: int) -> bytes: return struct.pack("<I", v & 0xFFFFFFFF)
def u64(v: int) -> bytes: return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)

def sign_detached(sk: signing.SigningKey, msg: bytes) -> bytes:
    return sk.sign(msg).signature

def verify_detached(vk: signing.VerifyKey, msg: bytes, sig: bytes) -> bool:
    try:
        vk.verify(msg, sig)
        return True
    except Exception:
        return False

def seal_to(pk_x25519: bytes, plaintext: bytes) -> bytes:
    box = public.SealedBox(public.PublicKey(pk_x25519))
    return box.encrypt(plaintext)

def unseal_with(sk_x25519: bytes, ciphertext: bytes) -> bytes:
    box = public.SealedBox(public.PrivateKey(sk_x25519))
    return box.decrypt(ciphertext)

