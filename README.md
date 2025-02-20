- Simple Encryption/Hashing Tool

It is a simple security tool that hashes text using SHA-256 or encrypts/decrypts text using AES-256


- Features
  
 SHA-256 Hashing: It hashes the input text using the SHA-256.

 AES-256 Encryption/Decryption:
	
 Generates a 256-bit AES key.

 Encrypts input text using AES in CBC mode.

 Decrypts the encrypted text to its original form.


- How to Use

1. Setup Environment

Install python and install the required cryptography library:

$  pip install cryptography

2. Execution of the Program

python encryption_tool.py

When executed, the program displays two choices:

1) SHA-256 Hashing(hash)

2) AES Encryption and Decryption (encrypt / decrypt)

Choose an option and then follow the instructions to see the results.


- Limitations

This tool is constructed for learning purposes and should not be utilized to encrypt sensitive information.

AES key is generated and not kept on hand when run.

There can be a problem with a fixed IV (Initialization Vector) in AES encryption.

- Ethical Implications

The tool is meant for the purposes of educational security principle learning and personal data protection technique learning.
It should never be employed in criminal usage such as circumventing encryption or accessing protected data without permission.


- License

This is an open-source project and can be redistributed and adapted under the terms of the selected license.

