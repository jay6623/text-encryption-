import hashlib
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def sha256_hash(text):
    """SHA-256 hashing function: Converts input text into a fixed-length hash."""
    hashed = hashlib.sha256(text.encode()).hexdigest()
    return hashed

def generate_aes_key():
    """Generates a random AES-256 key (32 bytes)."""
    return os.urandom(32)  # 256-bit key

def encrypt_aes(plain_text, key):
    """AES-256 encryption function using CBC mode."""
    iv = os.urandom(16)  # AES block size (128-bit)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Padding to make the text fit the AES block size (16 bytes)
    pad_length = 16 - (len(plain_text) % 16)
    padded_text = plain_text + chr(pad_length) * pad_length
    
    encrypted_bytes = encryptor.update(padded_text.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_bytes).decode()

def decrypt_aes(encrypted_text, key):
    """AES-256 decryption function."""
    encrypted_bytes = base64.b64decode(encrypted_text)
    iv = encrypted_bytes[:16]
    cipher_text = encrypted_bytes[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(cipher_text) + decryptor.finalize()
    
    # Removing padding after decryption
    pad_length = ord(decrypted_padded[-1:])
    return decrypted_padded[:-pad_length].decode()

if __name__ == "__main__":
    while True:
        print("🔐 Choose encryption/hashing tool")
        print("1. SHA-256 hashing")
        print("2. AES Encryption")
        choice = input("Select (1/2): ")
    
        if choice == "1":
            text = input("Enter the text to hash: ")
            print(f"SHA-256 hash: {sha256_hash(text)}")
            break;
        elif choice == "2":
            key = generate_aes_key()
            print(f"AES key: {base64.b64encode(key).decode()}")
        
            text = input("Enter the text to encrypt: ")
            encrypted = encrypt_aes(text, key)
            print(f"🛑 Encrypted text: {encrypted}")
        
            decrypted = decrypt_aes(encrypted, key)
            print(f"✅ Decrypted text: {decrypted}")
            break;
        else:
            print("Invalid choice, please select 1 or 2.")
            continue