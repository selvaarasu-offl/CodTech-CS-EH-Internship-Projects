AES-256-GCM File Encryptor
Lightweight Python tool to encrypt and decrypt files using AES-256-GCM authenticated encryption.

Features
Encrypt files securely with a passphrase.
Decrypt files encrypted by this tool.
Uses strong key derivation (PBKDF2 with 200,000 iterations).
Produces a compact binary output.

Requirements
Python 3.6+
cryptography package (pip install cryptography)

Usage:

Encrypt a file
python encrypt_tool.py encrypt --in secret.txt --out secret.bin
You will be prompted to enter and confirm a passphrase.

Decrypt a file
python encrypt_tool.py decrypt --in secret.bin --out secret.txt
You will be prompted to enter the passphrase used during encryption.

Notes
Original files are not deleted automatically.
Encrypted files are binary and unreadable without decryption.
Keep your passphrase safe — without it, decryption is impossible.
