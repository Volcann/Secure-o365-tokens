# 🔐 Encrypting Outlook Access and Refresh Tokens

## 1. Encrypting Outlook Access and Refresh Tokens Before Database Storage.
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
