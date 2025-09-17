import struct
from nacl import utils
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

FILE_NONCE_SIZE = 24
CHUNK_COUNTER_SIZE = 8

def generate_key() -> bytes:
    return utils.random(32)

def derive_chunk_nonce(file_nonce: bytes, counter: int) -> bytes:
    counter_bytes = struct.pack("<Q", counter)
    prefix = file_nonce[:FILE_NONCE_SIZE - CHUNK_COUNTER_SIZE]
    suffix = bytes(a ^ b for a, b in zip(file_nonce[-CHUNK_COUNTER_SIZE:], counter_bytes))
    return prefix + suffix

def encrypt_chunk(key: bytes, file_nonce: bytes, counter: int, chunk: bytes, aad: bytes) -> bytes:
    nonce = derive_chunk_nonce(file_nonce, counter)
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(chunk, aad, nonce, key)
    return ct