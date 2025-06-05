from cryptography.fernet import Fernet

# Generate a key for Fernet encryption
key = Fernet.generate_key()
cipher = Fernet(key)

# Sample plaintext to encrypt
plaintext = "user_id:42|timestamp:2025-06-04T10:00:00Z"

# Encrypt the provided string
token = cipher.encrypt(plaintext)

# Decrypt the token
decrypted = cipher.decrypt(token)

# Display results
print("Fernet Key:\n", key.decode())
print("\nEncrypted Token:\n", token.decode())
print("\nDecrypted Back to Original:\n", decrypted.decode())
