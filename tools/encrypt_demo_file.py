from __future__ import annotations

import os
from pathlib import Path

from secure.crypto import CryptoConfigError, generate_fernet_key_str
from secure.file_crypto import encrypt_file


def main() -> int:
    base_dir = Path("data")
    plaintext = base_dir / "demo_sensitive.json"
    encrypted = base_dir / "demo_sensitive.json.encrypted.json"

    if not plaintext.exists():
        raise FileNotFoundError(f"missing plaintext file: {plaintext}")

    if not os.getenv("DATA_ENCRYPTION_KEY"):
        print("DATA_ENCRYPTION_KEY is not set.")
        print("Generate one and export it, e.g. (bash):")
        print(f"  export DATA_ENCRYPTION_KEY='{generate_fernet_key_str()}'")
        print("Then re-run this script.")
        return 2

    try:
        encrypt_file(plaintext_path=plaintext, encrypted_path=encrypted, base_dir=base_dir)
    except CryptoConfigError as e:
        print(str(e))
        return 2

    print(f"Encrypted: {encrypted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
