# File: kms_token_encryptor.py

"""
AWS KMS Encryption/Decryption for Outlook OAuth2 Tokens
-------------------------------------------------------
This script demonstrates how to use AWS KMS to encrypt/decrypt Outlook tokens.
It uses boto3 to call KMS.Encrypt and KMS.Decrypt.

Prerequisites:
  1. AWS credentials configured (e.g., via ~/.aws/credentials or environment variables).
  2. A Customer Master Key (CMK) in KMS; note its Key ID or ARN.
  3. IAM permissions: kms:Encrypt, kms:Decrypt on the CMK.

Dependencies:
    pip install boto3 python-dotenv

Environment Variables (in .env or export beforehand):
    AWS_KMS_KEY_ID   → e.g., arn:aws:kms:us-east-1:123456789012:key/abcd-ef01-2345-6789-abcdef012345
    AWS_REGION       → e.g., us-east-1
"""

import os
import base64
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

def get_kms_client():
    region = os.getenv("AWS_REGION")
    if not region:
        raise ValueError("AWS_REGION environment variable is required")
    return boto3.client("kms", region_name=region)

def encrypt_token_kms(kms_client, key_id: str, plaintext: str) -> str:
    """
    Encrypts `plaintext` (UTF-8 string) using AWS KMS.
    Returns a Base64-encoded ciphertext blob.
    """
    try:
        resp = kms_client.encrypt(
            KeyId=key_id,
            Plaintext=plaintext.encode("utf-8")
        )
        ciphertext_blob = resp["CiphertextBlob"]  # bytes
        return base64.b64encode(ciphertext_blob).decode("utf-8")
    except ClientError as e:
        raise RuntimeError(f"KMS encryption failed: {e}")

def decrypt_token_kms(kms_client, b64_ciphertext: str) -> str:
    """
    Decrypts the Base64-encoded ciphertext blob (as produced above) via KMS.Decrypt.
    Returns the original plaintext string.
    """
    ciphertext_blob = base64.b64decode(b64_ciphertext)
    try:
        resp = kms_client.decrypt(CiphertextBlob=ciphertext_blob)
        plaintext_bytes = resp["Plaintext"]  # bytes
        return plaintext_bytes.decode("utf-8")
    except ClientError as e:
        raise RuntimeError(f"KMS decryption failed: {e}")

def main():
    # 1. Load KMS info
    key_id = os.getenv("AWS_KMS_KEY_ID")
    if not key_id:
        raise ValueError("AWS_KMS_KEY_ID environment variable is required")

    kms_client = get_kms_client()

    # 2. Dummy tokens
    dummy_access = "access_token_example_user_42"
    dummy_refresh = "refresh_token_example_user_42"
    print("\n[+] Original Access Token:", dummy_access)
    print("[+] Original Refresh Token:", dummy_refresh)

    # 3. Encrypt via KMS
    encrypted_access = encrypt_token_kms(kms_client, key_id, dummy_access)
    encrypted_refresh = encrypt_token_kms(kms_client, key_id, dummy_refresh)
    print("\n[+] Encrypted Access Token (Base64 KMS Blob):", encrypted_access)
    print("[+] Encrypted Refresh Token (Base64 KMS Blob):", encrypted_refresh)

    # 4. Decrypt to verify
    decrypted_access = decrypt_token_kms(kms_client, encrypted_access)
    decrypted_refresh = decrypt_token_kms(kms_client, encrypted_refresh)
    print("\n[+] Decrypted Access Token:", decrypted_access)
    print("[+] Decrypted Refresh Token:", decrypted_refresh)

if __name__ == "__main__":
    main()
