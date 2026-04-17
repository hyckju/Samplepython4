from __future__ import annotations

import os
from pathlib import Path

from secure.crypto import CryptoConfigError
from secure.file_crypto import decrypt_file


def main() -> int:
    base_dir = Path("data")
    encrypted = base_dir / "demo_sensitive.json.encrypted.json"
    decrypted = base_dir / "demo_sensitive.decrypted.json"

    if not encrypted.exists():
        raise FileNotFoundError(f"missing encrypted file: {encrypted}")

    if not os.getenv("DATA_ENCRYPTION_KEY"):
        print("DATA_ENCRYPTION_KEY is not set.")
        return 2

    try:
        decrypt_file(encrypted_path=encrypted, decrypted_path=decrypted, base_dir=base_dir)
    except CryptoConfigError as e:
        print(str(e))
        return 2

    print(f"Decrypted: {decrypted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
