# File: aes_token_encryptor.py

"""
AES‐GCM Encryption/Decryption for Outlook OAuth2 Tokens
--------------------------------------------------------
This script demonstrates:
1. Generating or loading a 256‐bit AES key (from environment or regenerated each run for dummy purposes).
2. Encrypting a dummy OAuth2 token with AES‐GCM.
3. Decrypting the ciphertext to retrieve the original token.
4. Printing both ciphertext (Base64) and decrypted token.

Dependencies:
    pip install cryptography python-dotenv
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

# Load .env (optional)—expects AES_KEY as 32-byte Base64 string
load_dotenv()

def load_or_generate_key():
    """
    Loads a 32-byte AES key from the AES_KEY environment variable (Base64‐encoded).
    If not present, generates a new key and prints out the Base64 value (for dummy/demo).
    """
    b64_key = os.getenv("AES_KEY")
    if b64_key:
        try:
            key = base64.b64decode(b64_key)
            if len(key) != 32:
                raise ValueError("AES_KEY must decode to 32 bytes.")
            return key
        except Exception as e:
            print(f"[!] Failed to decode AES_KEY: {e}. Generating a new key.")
    # No valid key found—generate a fresh one
    key = AESGCM.generate_key(bit_length=256)
    print("[!] No valid AES_KEY found. Generated new key (Base64):")
    print(base64.b64encode(key).decode())
    return key

def encrypt_token(aes_key: bytes, plaintext_token: str) -> str:
    """
    Encrypts `plaintext_token` (UTF‐8) under AES‐GCM with a random 12‐byte nonce.
    Returns the ciphertext as Base64: nonce || ciphertext || tag.
    """
    aesgcm = AESGCM(aes_key)
    # 12-byte nonce for GCM
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_token.encode("utf-8"), associated_data=None)
    # Prepend nonce so we can decrypt later: nonce + ciphertext
    blob = nonce + ciphertext
    return base64.b64encode(blob).decode("utf-8")

def decrypt_token(aes_key: bytes, b64_blob: str) -> str:
    """
    Decrypts a Base64 blob produced by `encrypt_token` to recover the original plaintext token.
    """
    blob = base64.b64decode(b64_blob)
    nonce = blob[:12]
    ct_and_tag = blob[12:]
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ct_and_tag, associated_data=None)
    return plaintext.decode("utf-8")

def main():
    # 1. Load or generate AES key
    aes_key = load_or_generate_key()

    # 2. Dummy token (in real life, replace with actual OAuth2 token strings)
    dummy_access_token = "access_token_example_user_42"
    dummy_refresh_token = "refresh_token_example_user_42"
    print("\n[+] Original Access Token:", dummy_access_token)
    print("[+] Original Refresh Token:", dummy_refresh_token)

    # 3. Encrypt both tokens
    encrypted_access = encrypt_token(aes_key, dummy_access_token)
    encrypted_refresh = encrypt_token(aes_key, dummy_refresh_token)
    print("\n[+] Encrypted Access Token (Base64):", encrypted_access)
    print("[+] Encrypted Refresh Token (Base64):", encrypted_refresh)

    # 4. Decrypt to verify
    decrypted_access = decrypt_token(aes_key, encrypted_access)
    decrypted_refresh = decrypt_token(aes_key, encrypted_refresh)
    print("\n[+] Decrypted Access Token:", decrypted_access)
    print("[+] Decrypted Refresh Token:", decrypted_refresh)

if __name__ == "__main__":
    main()
