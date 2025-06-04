<img src="https://user-images.githubusercontent.com/74038190/212284115-f47cd8ff-2ffb-4b04-b5bf-4d1c14c0247f.gif" width="100%">

# 🔐 Encrypting Outlook Access and Refresh Tokens

- **✅ Fernet Encryption (Symmetric Key)**
- Useable for enterprise-level solution? → Yes, with strict key management practices.
- **Core Encryption Library:** `cryptography`
- **Other Notable Packages:** `python-dotenv, base64, os`
  

- **✅ RSA Encryption (Asymmetric Key)Most prrefered **
- Useable for enterprise-level solution? → Yes, preferred when you need secure token sharing across multiple services or clients.
- **Core Encryption Library:** `cryptography`
- **Other Notable Packages:** `python-dotenv, base64, os`
  

- **✅ AES-GCM Encryption (Symmetric)**
- Useable for enterprise-level solution? → Yes, if you rotate keys via a secure vault (e.g., HashiCorp Vault or AWS Secrets Manager) and keep keys unreachable by attackers.
- **Core Encryption Library:** `cryptography`
- **Other Notable Packages:** `python-dotenv, base64, os`
  

- **✅ AWS KMS Encryption (Asymmetric or symmetric under the hood)**
- Useable for enterprise-level solution? → Yes, highly recommended when you want central key management, auditing, and rotation.
- **Core Encryption Library:** `boto3`
- **Other Notable Packages:** `python-dotenv, base64`

<img src="https://user-images.githubusercontent.com/74038190/212284115-f47cd8ff-2ffb-4b04-b5bf-4d1c14c0247f.gif" width="100%">

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

<img src="https://user-images.githubusercontent.com/74038190/212284115-f47cd8ff-2ffb-4b04-b5bf-4d1c14c0247f.gif" width="100%">

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

<img src="https://user-images.githubusercontent.com/74038190/212284115-f47cd8ff-2ffb-4b04-b5bf-4d1c14c0247f.gif" width="100%">

## 3. AES-GCM Encryption (Symmetric, Authenticated)

1. Create/load a 256-bit AES key (must be 32 bytes).
   * Store this key in an environment variable (Base64-encoded).
   * In our example (`aes_token_encryptor.py`), if `AES_KEY` isn’t set, we generate a random key and print it.
2. Encrypt a token under AES-GCM with a random 12-byte nonce:
   ```python
   from cryptography.hazmat.primitives.ciphers.aead import AESGCM
   import os, base64

   key = base64.b64decode(os.getenv("AES_KEY"))
   aesgcm = AESGCM(key)
   nonce = os.urandom(12)
   ciphertext = aesgcm.encrypt(nonce, token_bytes, associated_data=None)
   blob = nonce + ciphertext
   ciphertext_b64 = base64.b64encode(blob).decode()
   ```
3. Decrypt to verify:
   ```python
   blob = base64.b64decode(ciphertext_b64)
   nonce, ct_and_tag = blob[:12], blob[12:]
   plaintext = aesgcm.decrypt(nonce, ct_and_tag, associated_data=None).decode()
   ```

**Pros:**

* AES-GCM adds authenticity (integrity) check (via GCM tag).
* Faster than RSA.
* Nonce ensures unique ciphertexts even for same plaintext.

**Cons:**

* Single symmetric key: if leaked, all tokens compromised.
* Must use a fresh random nonce each time (our code does).
* Key rotation must be handled externally (e.g., Vault).

**Cost:**

* Only `cryptography` (open‐source) + slight CPU overhead.
* Developer time to manage the key (rotate, store, etc.).

---

### Setup & Example

1. Install dependencies:

   ```bash
   pip install cryptography python-dotenv
   ```
2. Create `.env`:

   ```bash
   AES_KEY=<Base64-encoded 32-byte string>
   ```

   — if you skip this, the script will generate one and print it.
3. Run the example:

   ```bash
   python aes_token_encryptor.py
   ```
   
<img src="https://user-images.githubusercontent.com/74038190/212284115-f47cd8ff-2ffb-4b04-b5bf-4d1c14c0247f.gif" width="100%">

## 4. AWS KMS Encryption (Cloud-Managed Keys)

1. Create or identify a Customer Managed Key (CMK) in AWS KMS.
2. Ensure your IAM principal has `kms:Encrypt` and `kms:Decrypt` on the CMK.
3. Encrypt tokens by calling `KMS.Encrypt` with the CMK ID:
   ```python
   resp = kms_client.encrypt(KeyId=CMK_ID, Plaintext=token_bytes)
   ciphertext_blob = resp["CiphertextBlob"]  # bytes
   ciphertext_b64 = base64.b64encode(ciphertext_blob).decode()
   ```
4. Decrypt by calling `KMS.Decrypt` on the stored blob:
   ```python
   blob = base64.b64decode(ciphertext_b64)
   resp = kms_client.decrypt(CiphertextBlob=blob)
   plaintext = resp["Plaintext"].decode()
   ```

**Pros:**

* KMS handles key storage, rotation, and auditing.
* No encryption keys stored in code or local machines.
* Easy integration with AWS roles and policies.

**Cons:**

* Requires AWS account/configuration.
* Slight latency (network call to KMS).
* You incur AWS KMS API charges (small per-request cost).

**Cost:**

* boto3 is free; AWS KMS charges apply (roughly \$0.03 per 10K requests as of writing).
* Developer time to set up IAM/KMS.

---

### Setup & Example

1. Install dependencies:

   ```bash
   pip install boto3 python-dotenv
   ```
2. Create `.env`:

   ```bash
   AWS_REGION=us-east-1
   AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/abcdef01-2345-6789-abcd-ef0123456789
   ```
3. Run the example:

   ```bash
   python kms_token_encryptor.py
   ```

<img src="https://user-images.githubusercontent.com/74038190/212284115-f47cd8ff-2ffb-4b04-b5bf-4d1c14c0247f.gif" width="100%">

## Summary of All Methods

| Method                       | Key Type                                 | Key Storage                           | Payload Size Limit         | Speed            | Use Case                               |
| ---------------------------- | ---------------------------------------- | ------------------------------------- | -------------------------- | ---------------- | -------------------------------------- |
| **Fernet**                   | Symmetric                                | Environment variable (32-byte Base64) | Unlimited (token bytes)    | Very fast        | Easy DB encryption                     |
| **RSA (OAEP)**               | Asymmetric                               | Local files / HSM                     | \~\~190 bytes (2048-bit)   | Moderate         | When you need public key distribution  |
| **AES-GCM**                  | Symmetric                                | Environment variable / Vault          | Unlimited (token bytes)    | Very fast        | Authenticated encryption               |
| **AWS KMS**                  | Asymmetric (or symmetric under the hood) | AWS KMS                               | Unlimited (via envelope)   | Slower (network) | Centralized key management (cloud)     |

<img src="https://user-images.githubusercontent.com/74038190/212284115-f47cd8ff-2ffb-4b04-b5bf-4d1c14c0247f.gif" width="100%">
