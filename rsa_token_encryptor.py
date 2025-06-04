import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# ------------------------------------------------------------
# STEP 1: Generate RSA key pair (only do this once)
# ------------------------------------------------------------

def generate_rsa_key_pair(private_key_path: str, public_key_path: str, key_size: int = 2048):
    """
    Generates an RSA key pair and writes them to files:
      - private_key_path  (PEM, encrypted with no password in this example)
      - public_key_path   (PEM)
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # Serialize and save private key (PEM, no encryption)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_path, "wb") as f:
        f.write(pem_private)
    os.chmod(private_key_path, 0o600)  # Tight file permissions

    # Extract and save public key (PEM)
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_path, "wb") as f:
        f.write(pem_public)


# Paths where the keys will be stored
PRIVATE_KEY_FILE = "rsa_private_key.pem"
PUBLIC_KEY_FILE = "rsa_public_key.pem"

# Generate keys if they don’t already exist
if not (os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE)):
    print("Generating RSA key pair...")
    generate_rsa_key_pair(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)
    print(f"  → Private key written to: {PRIVATE_KEY_FILE}")
    print(f"  → Public key written to:  {PUBLIC_KEY_FILE}")
else:
    print("RSA key pair already exists. Skipping generation.")


# ------------------------------------------------------------
# STEP 2: Load public key and encrypt a token
# ------------------------------------------------------------

def load_public_key(public_key_path: str):
    """
    Loads an RSA public key from a PEM file.
    """
    with open(public_key_path, "rb") as f:
        pem_data = f.read()
    public_key = serialization.load_pem_public_key(pem_data)
    return public_key


def encrypt_with_public_key(public_key, plaintext_bytes: bytes) -> bytes:
    """
    Encrypt the given plaintext using RSA + OAEP padding (SHA256).
    Returns the ciphertext bytes.
    """
    ciphertext = public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


# Load the public key
pub_key = load_public_key(PUBLIC_KEY_FILE)

# Token we want to encrypt
plaintext = "user_id:42|timestamp:2025-06-04T10:00:00Z"
plaintext_bytes = plaintext.encode("utf-8")

# Encrypt
encrypted_token_bytes = encrypt_with_public_key(pub_key, plaintext_bytes)
# If you need a string‐safe representation, you can Base64‐encode it:
import base64
encrypted_token_b64 = base64.b64encode(encrypted_token_bytes).decode("utf-8")

print("\nEncrypted token (base64):")
print(encrypted_token_b64)


# ------------------------------------------------------------
# STEP 3: Load private key and decrypt
# ------------------------------------------------------------

def load_private_key(private_key_path: str):
    """
    Loads an RSA private key from a PEM file (no password).
    """
    with open(private_key_path, "rb") as f:
        pem_data = f.read()
    private_key = serialization.load_pem_private_key(pem_data, password=None)
    return private_key


def decrypt_with_private_key(private_key, ciphertext: bytes) -> bytes:
    """
    Decrypts the given ciphertext using RSA + OAEP padding (SHA256).
    Returns the decrypted plaintext bytes.
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# Load private key
priv_key = load_private_key(PRIVATE_KEY_FILE)

# Decrypt back
try:
    # Decode from base64
    ciphertext_bytes = base64.b64decode(encrypted_token_b64)
    decrypted_bytes = decrypt_with_private_key(priv_key, ciphertext_bytes)
    decrypted_text = decrypted_bytes.decode("utf-8")
except Exception as e:
    decrypted_text = f"Decryption failed: {e}"

print("\nDecrypted text:")
print(decrypted_text)
