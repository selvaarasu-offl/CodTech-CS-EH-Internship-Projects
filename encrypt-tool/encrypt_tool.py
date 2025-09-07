import argparse, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from getpass import getpass

MAGIC = b"ENCTOOL1"
SALT_LEN = 16
NONCE_LEN = 12
KDF_ITERS = 200_000

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERS, backend=default_backend())
    return kdf.derive(password)

def encrypt_file(inpath, outpath, password):
    salt = os.urandom(SALT_LEN)
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    with open(inpath, "rb") as f:
        plaintext = f.read()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    with open(outpath, "wb") as fo:
        fo.write(MAGIC)
        fo.write(salt)
        fo.write(nonce)
        fo.write(ciphertext)
    print(f"Encrypted {inpath} -> {outpath}")

def decrypt_file(inpath, outpath, password):
    with open(inpath, "rb") as f:
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Not a file produced by this tool or corrupted.")
        salt = f.read(SALT_LEN)
        nonce = f.read(NONCE_LEN)
        ciphertext = f.read()
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError("Decryption failed. Wrong password or corrupted file.") from e
    with open(outpath, "wb") as fo:
        fo.write(plaintext)
    print(f"Decrypted {inpath} -> {outpath}")

def main():
    ap = argparse.ArgumentParser(description="AES-256-GCM file encrypt/decrypt")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_e = sub.add_parser("encrypt")
    p_e.add_argument("--in", dest="infile", required=True)
    p_e.add_argument("--out", dest="outfile", required=True)
    p_d = sub.add_parser("decrypt")
    p_d.add_argument("--in", dest="infile", required=True)
    p_d.add_argument("--out", dest="outfile", required=True)
    args = ap.parse_args()

    if args.cmd == "encrypt":
        pwd = getpass("Passphrase: ")
        pwd2 = getpass("Confirm passphrase: ")
        if pwd != pwd2:
            print("Passphrases do not match.", file=sys.stderr); sys.exit(2)
        encrypt_file(args.infile, args.outfile, pwd)
    else:
        pwd = getpass("Passphrase: ")
        decrypt_file(args.infile, args.outfile, pwd)

if __name__ == "__main__":
    main()
