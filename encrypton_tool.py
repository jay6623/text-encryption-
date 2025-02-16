import hashlib
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def sha256_hash(text):
    """SHA-256 해싱 함수"""
    hashed = hashlib.sha256(text.encode()).hexdigest()
    return hashed

def generate_aes_key():
    """랜덤 AES 키 생성 (256비트)"""
    return os.urandom(32)  # 256-bit key

def encrypt_aes(plain_text, key):
    """AES-256 암호화 함수"""
    iv = os.urandom(16)  # AES 블록 크기 (128비트)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 패딩 추가 (AES는 16바이트 블록 크기 필요)
    pad_length = 16 - (len(plain_text) % 16)
    padded_text = plain_text + chr(pad_length) * pad_length
    
    encrypted_bytes = encryptor.update(padded_text.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_bytes).decode()

def decrypt_aes(encrypted_text, key):
    """AES-256 복호화 함수"""
    encrypted_bytes = base64.b64decode(encrypted_text)
    iv = encrypted_bytes[:16]
    cipher_text = encrypted_bytes[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(cipher_text) + decryptor.finalize()
    
    # 패딩 제거
    pad_length = ord(decrypted_padded[-1:])
    return decrypted_padded[:-pad_length].decode()

if __name__ == "__main__":
    while True:
        print("🔐 choose encrypt/hasing tool")
        print("1. SHA-256 hashing")
        print("2. AES Encryption")
        choice = input("select (1/2): ")
    
        if choice == "1":
            text = input("type the texts to encrypt: ")
            print(f"SHA-256 hash: {sha256_hash(text)}")
            break;
        elif choice == "2":
            key = generate_aes_key()
            print(f"AES key: {base64.b64encode(key).decode()}")
        
            text = input("type the texts to encrypt: ")
            encrypted = encrypt_aes(text, key)
            print(f"🛑 encrypted text: {encrypted}")
        
            decrypted = decrypt_aes(encrypted, key)
            print(f"✅ decrypted text: {decrypted}")
            break;
        else:
            print("invalid choice")
