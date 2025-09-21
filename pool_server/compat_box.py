# compat_box.py
from nacl.bindings import (
    crypto_box_beforenm,
    crypto_box_easy_afternm,
    crypto_box_open_easy_afternm,
)
import nacl.public

def crypto_box_easy(msg: bytes, nonce: bytes, pk: bytes, sk: bytes) -> bytes:
    """Equivalent to libsodium crypto_box_easy"""
    # Precompute shared key
    precomp = crypto_box_beforenm(pk, sk)
    # Encrypt
    return crypto_box_easy_afternm(msg, nonce, precomp)

def crypto_box_open_easy(ct: bytes, nonce: bytes, pk: bytes, sk: bytes) -> bytes:
    """Equivalent to libsodium crypto_box_open_easy"""
    precomp = crypto_box_beforenm(pk, sk)
    return crypto_box_open_easy_afternm(ct, nonce, precomp)

