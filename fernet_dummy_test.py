import os
from cryptography.fernet import Fernet, InvalidToken

# Generate a dummy Fernet key and set it as an environment variable
dummy_key = Fernet.generate_key().decode()
os.environ["FERNET_KEY"] = dummy_key

# Initialize Fernet with the dummy key
fernet = Fernet(dummy_key.encode())

# Sample plaintext to encrypt
plaintext = "user_id:42|timestamp:2025-06-04T10:00:00Z"

# Encrypt the plaintext
encrypted_token = fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

# Decrypt back to verify
try:
    decrypted_text = fernet.decrypt(encrypted_token.encode("utf-8")).decode("utf-8")
except InvalidToken:
    decrypted_text = "Decryption failed: Invalid token"

# Display results
encrypted_token, decrypted_text