import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Default path to store the key
DEFAULT_KEY_PATH = 'guardedim_key.bin'


def generate_key(path: str = DEFAULT_KEY_PATH) -> bytes:
    """
    Generate a new 256-bit AES key and save it to the given file path.
    """
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
    """
    Load the 256-bit AES key from the given file path.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Key file missing: {path}")
    try:
        with open(path, 'rb') as f:
            key = f.read()
        if len(key) != 32:
            raise ValueError(f"Invalid key length: {len(key)} bytes (expected 32)")
        return key
    except Exception as e:
        logging.error(f"Key load error: {e}")
        raise


def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = None) -> bytes:
    """
    Encrypt the plaintext using AES256-GCM.
    Output = nonce (12 bytes) || ciphertext || tag (16 bytes)
    """
    associated_data = associated_data or b''
    nonce = os.urandom(12)  # 96-bit nonce as required by AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt(payload: bytes, key: bytes, associated_data: bytes = None) -> bytes:
    """
    Decrypt the AES256-GCM encrypted payload.
    Assumes payload = nonce (12 bytes) || ciphertext + tag (16 bytes)
    """
    associated_data = associated_data or b''
    if len(payload) < 28:
        raise ValueError("Invalid payload length (must be at least 28 bytes)")

    nonce = payload[:12]
    ct_and_tag = payload[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ct_and_tag, associated_data)
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        raise


if __name__ == '__main__':
    # Self-test: encryption and decryption cycle
    key = generate_key()
    message = b"Hello, GuardedIM!"
    encrypted = encrypt(message, key)
    decrypted = decrypt(encrypted, key)
    assert decrypted == message
    print("AES256-GCM test passed.")
