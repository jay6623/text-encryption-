- Simple Encryption/Hashing Tool

This project provides a simple security tool that allows users to either hash text using SHA-256 or encrypt/decrypt text using AES-256.

- Features

* SHA-256 Hashing: Hashes the input text using the SHA-256 algorithm.

*AES-256 Encryption/Decryption:

* Generates a 256-bit AES key.

* Encrypts input text using AES in CBC mode.

* Decrypts the encrypted text back to its original form.

- How to Use

1. Setup Environment

Make sure Python is installed and install the required cryptography library:

pip install cryptography

2. Run the Program

python encryption_tool.py

When the program runs, you will be presented with two options:

SHA-256 Hashing

AES Encryption and Decryption

Choose an option and follow the prompts to see the results.

Limitations

This tool is for educational purposes only and should not be used for securing sensitive data without additional security considerations.

The AES key is randomly generated during execution and is not stored.

Using a fixed IV (Initialization Vector) in AES encryption can lead to security vulnerabilities.

Ethical Considerations

This tool is intended for learning security concepts and understanding personal data protection methods. It should not be used for malicious purposes such as bypassing encryption or unauthorized access to protected information.

📜 License

This project is open-source and can be modified and distributed under the terms of the selected license.

