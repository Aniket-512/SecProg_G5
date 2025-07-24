import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_KEY_PATH = 'guardedim_key.bin'

def generate_key(path: str = DEFAULT_KEY_PATH) -> bytes:
    key = AESGCM.generate_key(bit_length=256)
    try:
        with open(path, 'wb') as f:
            f.write(key)
        logging.info(f"Generated AES256-GCM key at {path}")
    except Exception as e:
        logging.error(f"Key save error: {e}")
        raise
    return key

def load_key(path: str = DEFAULT_KEY_PATH) -> bytes:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Key file missing: {path}")
    try:
        with open(path, 'rb') as f:
            key = f.read()
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes (found {len(key)})")
        return key
    except Exception as e:
        logging.error(f"Key load error: {e}")
        raise

def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = None) -> bytes:
    associated_data = associated_data or b''
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext

def decrypt(payload: bytes, key: bytes, associated_data: bytes = None) -> bytes:
    associated_data = associated_data or b''
    if len(payload) < 28:
        raise ValueError("Invalid payload length for AES256-GCM")

    nonce = payload[:12]
    ct_and_tag = payload[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ct_and_tag, associated_data)
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        raise

if __name__ == '__main__':
    key = generate_key()
    msg = b"Hello, GuardedIM!"
    ct = encrypt(msg, key)
    pt = decrypt(ct, key)
    assert pt == msg
    print("✅ AES256-GCM test passed.")
