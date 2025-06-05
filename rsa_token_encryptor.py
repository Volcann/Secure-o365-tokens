import os
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------
# STEP 1: Generate RSA key pair (exactly as you had it)
# ---------------------------------------------------------------------

def generate_rsa_key_pair(private_key_path: str, public_key_path: str, key_size: int = 2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    # Serialize & save private key (PEM, no passphrase)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_path, "wb") as f:
        f.write(pem_private)
    os.chmod(private_key_path, 0o600)

    # Extract & save public key (PEM)
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_path, "wb") as f:
        f.write(pem_public)


PRIVATE_KEY_FILE = "rsa_private_key.pem"
PUBLIC_KEY_FILE = "rsa_public_key.pem"

if not (os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE)):
    print("Generating RSA key pair...")
    generate_rsa_key_pair(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)
    print(f"  → Private key written to: {PRIVATE_KEY_FILE}")
    print(f"  → Public key written to:  {PUBLIC_KEY_FILE}")
else:
    print("RSA key pair already exists. Skipping generation.")

# ---------------------------------------------------------------------
# STEP 2: Load RSA public key from PEM
# ---------------------------------------------------------------------

def load_public_key(public_key_path: str):
    with open(public_key_path, "rb") as f:
        pem_data = f.read()
    public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())
    return public_key

def load_private_key(private_key_path: str):
    with open(private_key_path, "rb") as f:
        pem_data = f.read()
    private_key = serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
    return private_key


# ---------------------------------------------------------------------
# STEP 3: Hybrid Encryption (RSA + AES-GCM)
# ---------------------------------------------------------------------

def hybrid_encrypt(public_key, plaintext: bytes) -> bytes:
    """
    1. Generate a random 32-byte AES key.
    2. Encrypt plaintext under AES-256-GCM → (iv, ciphertext, tag).
    3. Encrypt AES key under RSA/OAEP.
    4. Return a single blob: RSA_ENC_KEY || IV || TAG || AES_CIPHERTEXT, all base64-encoded.
    """
    # 1. Generate a random 32-byte AES key
    aes_key = os.urandom(32)  # AES-256

    # 2. Encrypt plaintext under AES-GCM
    iv = os.urandom(12)  # 96-bit nonce is typical for GCM
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag  # 16 bytes

    # 3. Encrypt the AES key under RSA/OAEP
    rsa_encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # 4. Concatenate: [ rsa_encrypted_key || iv || tag || ciphertext ] and base64 encode everything
    combined = b"".join([
        len(rsa_encrypted_key).to_bytes(4, "big"),
        rsa_encrypted_key,
        iv,
        tag,
        ciphertext
    ])
    return base64.b64encode(combined)


def hybrid_decrypt(private_key, b64_blob: bytes) -> bytes:
    """
    1. Decode base64.
    2. Extract RSA_ENC_KEY length, RSA_ENC_KEY, IV, TAG, AES_CIPHERTEXT.
    3. RSA-decrypt the AES key.
    4. AES-GCM decrypt the ciphertext.
    5. Return plaintext.
    """
    combined = base64.b64decode(b64_blob)
    # First 4 bytes = length of the RSA_encrypted_key
    rsa_key_len = int.from_bytes(combined[:4], "big")
    offset = 4

    rsa_encrypted_key = combined[offset : offset + rsa_key_len]
    offset += rsa_key_len

    iv = combined[offset : offset + 12]
    offset += 12

    tag = combined[offset : offset + 16]
    offset += 16

    ciphertext = combined[offset : ]

    # Decrypt AES key with RSA
    aes_key = private_key.decrypt(
        rsa_encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Now decrypt the ciphertext under AES-GCM
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


# ---------------------------------------------------------------------
# STEP 4: Use hybrid_encrypt / hybrid_decrypt instead of raw RSA
# ---------------------------------------------------------------------

# Load RSA keys
pub_key = load_public_key(PUBLIC_KEY_FILE)
priv_key = load_private_key(PRIVATE_KEY_FILE)

# This is your very large JWT‐string
plaintext = (
    "eyJ0eXAiOiJKV1QiLCJub25jZSI6IklUeFJ3WnN2Q0tuT1JTZ1cxVm5ORlBoQWtpcTRobjh6cmoxNVNlNndfUVUiLCJhbGciOiJSUzI1NiIsIng1dCI6IkNOdjBPSTNSd3FsSEZFVm5hb01Bc2hDSDJYRSIsImtpZCI6IkNOdjBPSTNSd3FsSEZFVm5hb01Bc2hDSDJYRSJ9."
    "eyJhdWQiOiIwMDAwMDAwMy0wMDAwLTAwMDAtYzAwMC0wMDAwMDAwMDAwMDAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9iMzg2ZTQyOS0xZmU2LTQ1OTQtYjYzNS05ZjUyMzE4MzgwOTUvIiwiaWF0IjoxNzQ1NDE0Mzc0LCJuYmYiOjE3NDU0MTQzNzQsImV4cCI6MTc0NTQxODg2OSwiYWNjdCI6MCwiYWNyIjoiMSIsImFpbyI6IkFVUUF1LzhaQUFBQVpoNUNpZGFhS0pmOVFIR2tJRTRsai80Y1VWcFNnbktRZHFndXdNU0U0N25XVk9wKzIzeVRZUkVvc0k5LzA1eGVVR3pFSWlEdndtL1EwdkFBMlY2RUdBPT0iLCJhbXIiOlsicHdkIl0sImFwcF9kaXNwbGF5bmFtZSI6IkVDUE1QIERldiIsImFwcGlkIjoiZWU0Yjg4NDItMDMwYi00M2Q4LTlhMWUtZWY2ZGFhOTU5ZWY2IiwiYXBwaWRhY3IiOiIxIiwiZmFtaWx5X25hbWUiOiJGaW5ldHRlLUNvbnN0YW50aW4iLCJnaXZlbl9uYW1lIjoiU29waGllIiwiaWR0eXAiOiJ1c2VyIiwiaXBhZGRyIjoiMmEwMTpjYjE1Ojg5MDg6NzcwMDozZGFiOmE4M2I6YjJhNTo2MDgwIiwibmFtZSI6InNvcGhpZSBmaW5ldHRlLWNvbnN0YW50aW4iLCJvaWQiOiJmZjMwZGUwOS1lMGQ5LTQ1MTUtYjBjNS1mYmZjYzdiNWE2ODAiLCJwbGF0ZiI6IjMiLCJwdWlkIjoiMTAwMzIwMDM2MEI5MDIyMCIsInJoIjoiMS5BVEVBS2VTR3MtWWZsRVcyTlo5U01ZT0FsUU1BQUFBQUFBQUF3QUFBQUFBQUFBQk5BVUl4QUEuIiwic2NwIjoiQ2FsZW5kYXJzLlJlYWQgRmlsZXMuUmVhZCBGaWxlcy5SZWFkLkFsbCBGaWxlcy5SZWFkV3JpdGUgRmlsZXMuUmVhZFdyaXRlLkFsbCBTaXRlcy5SZWFkLkFsbCBTaXRlcy5SZWFkV3JpdGUuQWxsIFVzZXIuUmVhZCBwcm9maWxlIG9wZW5pZCBlbWFpbCIsInNpZCI6IjAwMmZhMzY5LTM3MjYtOTQ0ZS1kNDZjLTUyMGNkNzIyY2JjZCIsInNpZ25pbl9zdGF0ZSI6WyJrbXNpIl0sInN1YiI6ImhsRnBCMGIzeEtkNHp3eEpCNk1XLVNyM0Y1OFBpWEdGMzNKZXZPcDRwS1EiLCJ0ZW5hbnRfcmVnaW9uX3Njb3BlIjoiRVUiLCJ0aWQiOiJiMzg2ZTQyOS0xZmU2LTQ1OTQtYjYzNS05ZjUyMzE4MzgwOTUiLCJ1bmlxdWVfbmFtZSI6InNvcGhpZS5maW5ldHRlLWNvbnN0YW50aW5Ac2hhcmVtdW5kby5jb20iLCJ1cG4iOiJzb3BoaWUuZmluZXR0ZS1jb25zdGFudGluQHNoYXJlbXVuZG8uY29tIiwidXRpIjoiVWVuSURoLUxCVUNLckJ3ZnloUTdBQSIsInZlciI6IjEuMCIsIndpZHMiOlsiYjc5ZmJmNGQtM2VmOS00Njg5LTgxNDMtNzZiMTk0ZTg1NTA5Il0sInhtc19mdGQiOiJ4cDRvOTBZUUFlVGRac05YWUxSS2psTnMxN1lULTM2WWttWlV2TW5jMmtBIiwieG1zX2lkcmVsIjoiMSAyMiIsInhtc19zdCI6eyJzdWIiOiJJMW9HNjV2c2NfT0liWHZQd2phSkt3OVBtaTFYZGF0UEJDdXVfRE5zZktrIn0sInhtc190Y2R0IjoxNTMyNzcwMjM5LCJ4bXNfdGRiciI6IkVVIn0sInhtc19pZHJlbCI6IjEiOjAiLCJ4bXMuc3QiOnsic3ViIjoiSTFvRzY1dnNjX09JYlh2UHdqYUpLdzlQbWkxWERhdFBCQ3V1X0ROc2ZLIn19LCJ4bXMtdGNkcSI6MTUzMjc3MDIzOSwid2lkcyI6WyJiNzlmYmY0ZC0zZWY5LTQ2ODktODE0My03NmIxOTRlODU1MDkiXSwieG1zX2lkcmVsIjoiMSAyMiJ9. boPTmVdY9UjvvZFdCtwWRezR7f5wn9GEYkOMvLNozxCprJUD2_LXzriijwINUn83tw-mHi1hGBgENsGKSP8XyDOChBWpvDOWc_B_BsvGAXKQEqhw2Y9z3qnpm2Eag8sbzVCn5nM8K_GNplmLvzxHpDu7JdCiN1uLP4vrf4Z42NDMrbmt9bu4eIYd5OuwRgHR8CkSJuu4FfFGd-HSNTektlK4XY2UWTYeMT5H0cKskudsXqJyOkpBIRFkBOzmMsaYpijvSpARo-laRsb02ge5XFDxu4TAnc_S8l41Og6OkaID1hA-PjrtdkiUgGSQSR9n7P_VJtmfiA9rJ-99L8cp5w"
).encode('utf-8')

# Encrypt using hybrid scheme
encrypted_blob_b64 = hybrid_encrypt(pub_key, plaintext)
print("\nEncrypted payload (base64):")
print(encrypted_blob_b64.decode("utf-8"))

# Decrypt back
try:
    decrypted_bytes = hybrid_decrypt(priv_key, encrypted_blob_b64)
    decrypted_text = decrypted_bytes.decode("utf-8")
except Exception as e:
    decrypted_text = f"Decryption failed: {e}"

print("\nDecrypted text:")
print(decrypted_text)

if decrypted_text == plaintext.decode("utf-8"):
    print("\nMatch? --> True")
else:
    print("\nMatch? --> False")