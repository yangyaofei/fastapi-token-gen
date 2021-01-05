from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256, Hash
import os


def encrypt(payload: bytes, key: bytes, none: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key=key)
    ct = chacha.encrypt(none, payload, None)
    return ct


def decrypt(payload: bytes, key: bytes, none: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key=key)
    ct = chacha.decrypt(none, payload, None)
    return ct


def gen_key(key: bytes):
    digest = Hash(SHA256())
    digest.update(key)
    hash_bytes = digest.finalize()
    return hash_bytes[:32]


def gen_none_from_timestamp(timestamp: int):
    digest = Hash(SHA256())
    digest.update(str(timestamp).encode("utf-8"))
    hash_bytes = digest.finalize()
    return hash_bytes[:12]
