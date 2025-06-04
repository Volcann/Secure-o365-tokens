# 🔐 Encrypting Outlook Access and Refresh Tokens

- ✅ Fernet Encryption (Symmetric Key)
Useable for enterprise-level solution? → Yes, with strict key management practices.
- ✅ RSA Encryption (Asymmetric Key)
Useable for enterprise-level solution? → Yes, preferred when you need secure token sharing across multiple services or clients.

## 1. Encrypting Outlook Access and Refresh Tokens Before Database Storage through Fernet Encryption.
1. Before saving your Outlook OAuth2 tokens, use a secret Fernet key (32-byte) to encrypt them with Python’s `cryptography` package.
2. Store the encrypted tokens (ciphertexts) in your Django database using `EncryptedCharField` or manual encryption in CharFields.
3. When you need to refresh the session, decrypt the tokens with the same Fernet key to get the original tokens and proceed with the OAuth2 flow.

**Pros:**

* Keeps tokens safe in the database (no plain text exposure).
* Easy to implement using Python’s built-in `cryptography` library and Django fields.
* Even if someone steals the database, they can’t read tokens without the Fernet key.

**Cons:**

* You must securely manage and rotate the Fernet key (if it’s leaked, encryption is useless).
* Adds a small performance overhead to encrypt/decrypt on every save or read.
* If the key is lost, you permanently lose access to stored tokens.

**Costing:**

* The `cryptography` package and Django fields are open-source and free to use.
* Extra CPU usage for encryption/decryption is minimal and won’t increase hosting costs noticeably.
* Your only real cost is development time to set up environment variables and code integration.

---

## ⚙️ Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/Volcann/Secure-o365-tokens.git
pip install cryptography python-dotenv
python fernet_dummy_test.py
```

## 2. Encrypting Tokens with RSA Public/Private Key Pair Before Storage or Transmission

1. Generate an RSA key pair once (e.g., using Python’s `cryptography` library):
   * Save the private key to `rsa_private_key.pem` with tight permissions (`chmod 600`).
   * Save the public key to `rsa_public_key.pem`.
2. Distribute only `rsa_public_key.pem` to any service or client that needs to encrypt tokens.
3. When creating a token (for example, `"user_id:42|timestamp:2025-06-04T10:00:00Z"`), load the public key and encrypt the plaintext using RSA-OAEP (SHA-256).
4. Base64-encode the resulting ciphertext if you need a URL- or database-friendly string.
5. Store or transmit the encrypted token (ciphertext) as needed.

**Pros:**

* Asymmetric security boundary: only the private key can decrypt. Even if someone steals the public key, they cannot recover the token.
* Public keys can be freely distributed to microservices, mobile clients, etc., without exposing decryption capability.
* Standardized and battle-tested: RSA with OAEP (SHA-256) is a well-known, widely audited scheme.

**Cons:**

* Payload size limit: RSA-OAEP can only encrypt relatively small data (roughly \~190 bytes with a 2048-bit key and SHA-256). For longer tokens, you must use a hybrid approach (e.g., encrypt a symmetric key with RSA, then encrypt the token with that symmetric key).
* Performance overhead: RSA encryption/decryption is slower than symmetric schemes (like Fernet).
* Key management complexity: You must protect, rotate, and back up the private key. Mismanaging it invalidates the entire system.

**Costing:**

* The `cryptography` package and OpenSSL are open-source and free to use.
* RSA operations incur extra CPU usage, but for typical web-scale usage, this overhead is minimal and won’t noticeably increase hosting costs.
* Primary “cost” is development time to set up key generation, secure storage of the private key, and integration into your token workflow.

---

## ⚙️ Setup Instructions

### 1. Install Dependencies

```bash
pip install cryptography
```

### 2. Create the Script File

Save the following Python code (shown previously) in a file named `rsa_token_encryptor.py`. This script will:

1. Generate `rsa_private_key.pem` and `rsa_public_key.pem` (if they don’t already exist).
2. Encrypt a sample token with the public key and print its Base64 ciphertext.
3. Decrypt it back with the private key to verify.

### 3. Run and Verify

```bash
git clone https://github.com/Volcann/Secure-o365-tokens.git
python rsa_token_encryptor.py
```

* Ensure `rsa_private_key.pem` is protected (`chmod 600 rsa_private_key.pem`).
* Distribute only `rsa_public_key.pem` to any service or client that needs to encrypt tokens.
* Keep `rsa_private_key.pem` safely on your server under strict permissions.
