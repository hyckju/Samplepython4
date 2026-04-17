## Demo: fake sensitive data + encryption (safe)

This folder contains helper scripts that:
1) generate *fake* sensitive-looking data (intentionally invalid identifiers)
2) encrypt/decrypt using `DATA_ENCRYPTION_KEY` (Fernet)

By default, use the **no-plaintext** flow so the sensitive-looking plaintext is not written to disk.

### 1) Generate + encrypt (recommended: no plaintext file)

```bash
python tools/generate_and_encrypt_demo_file.py
```

Output:
- `data/demo_sensitive.json.encrypted.json`

### 2) (Optional) Generate plaintext file (for demo only)

```bash
python tools/generate_fake_sensitive_file.py
```

Output:
- `data/demo_sensitive.json`

### 3) Set encryption key (do NOT commit real keys)

Generate a Fernet key (example):

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Export it (bash/WSL):

```bash
export DATA_ENCRYPTION_KEY='PASTE_KEY_HERE'
```

PowerShell:

```powershell
$env:DATA_ENCRYPTION_KEY = "PASTE_KEY_HERE"
```

### 4) Encrypt (plaintext -> encrypted)

```bash
python tools/encrypt_demo_file.py
```

Output:
- `data/demo_sensitive.json.encrypted.json`

### 5) Decrypt (verification)

```bash
python tools/decrypt_demo_file.py
```

Output:
- `data/demo_sensitive.decrypted.json`

### Tests

```bash
python -m unittest -q
```
