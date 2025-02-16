"""
Encryption and Hashing Utility

This script provides two functionalities:
1. SHA-256 hashing: Converts input text into a fixed-length hash (one-way encryption).
2. AES-256 encryption/decryption: Encrypts and decrypts text using AES-256 with CBC mode.

Author: Dongjoo LEe
Date: Feburary,16, 2025
"""

import hashlib
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def sha256_hash(text):
    """Computes the SHA-256 hash of the given text."""
    return hashlib.sha256(text.encode()).hexdigest()

def generate_aes_key():
    """Generates a random 256-bit (32-byte) AES key."""
    return os.urandom(32)

def encrypt_aes(plain_text, key):
    """Encrypts the given text using AES-256 in CBC mode."""
    iv = os.urandom(16)  # AES block size (128-bit)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Padding to align with AES block size (16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_text = padder.update(plain_text.encode()) + padder.finalize()
    
    encrypted_bytes = encryptor.update(padded_text) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_bytes).decode()

def decrypt_aes(encrypted_text, key):
    """Decrypts AES-256 encrypted text."""
    encrypted_bytes = base64.b64decode(encrypted_text)
    iv = encrypted_bytes[:16]  # Extract IV
    cipher_text = encrypted_bytes[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(cipher_text) + decryptor.finalize()
    
    # Removing padding after decryption
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_text = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted_text.decode()

if __name__ == "__main__":
    while True:
        print("🔐 Choose encryption/hashing tool")
        print("1. SHA-256 hashing (cannot be decrypted)")
        print("2. AES Encryption")
        choice = input("Select (1/2): ")
    
        if choice == "1":
            text = input("Enter the text to hash: ")
            print(f"SHA-256 hash: {sha256_hash(text)}")
            break
        elif choice == "2":
            key = generate_aes_key()
            print(f"AES key: {base64.b64encode(key).decode()}")
        
            text = input("Enter the text to encrypt: ")
            encrypted = encrypt_aes(text, key)
            print(f"Encrypted text: {encrypted}")
        
            decrypted = decrypt_aes(encrypted, key)
            print(f"Decrypted text: {decrypted}")
            break
        else:
            print("Invalid choice, please select 1 or 2.")
            continue
