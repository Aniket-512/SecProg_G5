#!/usr/bin/env python3
"""
Group 5 Crypto Module
AES256-GCM encryption implementation
96-bit nonce with authenticated encryption
"""

import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Encryption configuration
DEFAULT_KEY_PATH = 'group5_key.bin'
NONCE_LENGTH = 12  # 96 bits

def generate_key(path: str = DEFAULT_KEY_PATH) -> bytes:
    """
    Generate AES256-GCM encryption key per specification section 4:
    "AES256-GCM is used as it is part of the Commercial National Security Algorithm Suite"
    
    Returns:
        bytes: 256-bit (32 bytes) AES key
    """
    key = AESGCM.generate_key(bit_length=256)
    try:
        with open(path, 'wb') as f:
            f.write(key)
        logging.info(f"Generated AES256-GCM key at {path}")
    except Exception as e:
        logging.error(f"Key generation error: {e}")
        raise
    return key

def load_key(path: str = DEFAULT_KEY_PATH) -> bytes:
    """
    Load AES256-GCM encryption key from file
    
    Returns:
        bytes: 256-bit AES key
        
    Raises:
        FileNotFoundError: If key file doesn't exist
        ValueError: If key length is invalid
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Key file not found: {path}")
    
    try:
        with open(path, 'rb') as f:
            key = f.read()
        
        if len(key) != 32:  # 256 bits = 32 bytes
            raise ValueError(f"Invalid key length: {len(key)} bytes (expected 32)")
        
        logging.debug(f"Loaded AES256-GCM key from {path}")
        return key
        
    except Exception as e:
        logging.error(f"Key loading error: {e}")
        raise

def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = None) -> bytes:
    """
    Encrypt data using AES256-GCM per specification section 4
    
    Packet format per specification:
    • Nonce/IV (96 bits = 12 bytes)
    • Payload (encrypted data)
    • Authentication tag (128 bits = 16 bytes, included in AESGCM output)
    
    Args:
        plaintext: Data to encrypt
        key: 256-bit AES key
        associated_data: Optional associated data for authentication
        
    Returns:
        bytes: nonce (12 bytes) + ciphertext + tag
    """
    if len(key) != 32:
        raise ValueError("Key must be 256 bits (32 bytes)")
        
    associated_data = associated_data or b''
    
    # Generate 96-bit nonce per specification
    nonce = os.urandom(NONCE_LENGTH)
    
    # Encrypt with AES256-GCM
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    
    # Return: nonce + ciphertext + tag (as per specification)
    return nonce + ciphertext_with_tag

def decrypt(payload: bytes, key: bytes, associated_data: bytes = None) -> bytes:
    """
    Decrypt AES256-GCM encrypted data per specification section 4
    
    Args:
        payload: Encrypted data (nonce + ciphertext + tag)
        key: 256-bit AES key  
        associated_data: Optional associated data for authentication
        
    Returns:
        bytes: Decrypted plaintext
        
    Raises:
        ValueError: If payload format is invalid or authentication fails
    """
    if len(key) != 32:
        raise ValueError("Key must be 256 bits (32 bytes)")
        
    # Minimum length: 12 bytes (nonce) + 16 bytes (tag) = 28 bytes
    if len(payload) < 28:
        raise ValueError("Invalid payload length (minimum 28 bytes required)")

    associated_data = associated_data or b''
    
    # Extract nonce and ciphertext+tag
    nonce = payload[:NONCE_LENGTH]
    ciphertext_with_tag = payload[NONCE_LENGTH:]
    
    # Decrypt and authenticate
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return plaintext
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        raise ValueError(f"Decryption or authentication failed: {e}")

def get_packet_info(payload: bytes) -> dict:
    """
    Analyze encrypted packet structure per specification
    
    Returns:
        dict: Packet information (nonce, payload size, etc.)
    """
    if len(payload) < 28:
        return {"error": "Invalid packet length"}
    
    nonce = payload[:NONCE_LENGTH]
    ciphertext_with_tag = payload[NONCE_LENGTH:]
    
    return {
        "total_size": len(payload),
        "nonce_size": len(nonce),
        "nonce_hex": nonce.hex(),
        "ciphertext_with_tag_size": len(ciphertext_with_tag),
        "valid_format": True
    }

# Self-test functionality
def self_test():
    """Test AES256-GCM encryption/decryption cycle"""
    print("Testing GuardedIM crypto module...")
    
    # Generate test key
    test_key = AESGCM.generate_key(bit_length=256)
    
    # Test messages
    test_messages = [
        b"Hello, GuardedIM!",
        b"This is a test message for AES256-GCM encryption",
        b'{"type":"message","from":"alice","to":"bob","payload":"Hello Bob!"}',
        b"A" * 4096,  # Test with maximum text size per specification
    ]
    
    for i, message in enumerate(test_messages, 1):
        try:
            # Encrypt
            encrypted = encrypt(message, test_key)
            
            # Verify packet structure
            info = get_packet_info(encrypted)
            assert info["nonce_size"] == 12, "Nonce must be 96 bits (12 bytes)"
            assert info["total_size"] >= 28, "Minimum packet size is 28 bytes"
            
            # Decrypt
            decrypted = decrypt(encrypted, test_key)
            
            # Verify
            assert decrypted == message, f"Test {i}: Decryption mismatch"
            print(f"[OK] Test {i}: {len(message)} bytes encrypted/decrypted successfully")
            
        except Exception as e:
            print(f"[ERROR] Test {i} failed: {e}")
            return False
    
    print("[SUCCESS] All AES256-GCM tests passed!")
    return True

if __name__ == '__main__':
    # Run self-test when module executed directly
    logging.basicConfig(level=logging.INFO)
    
    success = self_test()
    
    if success:
        print("\n[SECURE] GuardedIM crypto module is specification compliant!")
        print("- AES256-GCM encryption [OK]")
        print("- 96-bit nonce generation [OK]") 
        print("- Commercial NSA Suite compliant [OK]")
    else:
        print("\n[FAILED] Crypto module tests failed!")
        exit(1)