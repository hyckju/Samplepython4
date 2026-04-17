from __future__ import annotations

import json
import os
from pathlib import Path

from secure.crypto import CryptoConfigError, generate_fernet_key_str
from secure.file_crypto import encrypt_bytes_to_envelope_file
from tools.generate_fake_sensitive_file import build_fake_sensitive_payload


def main() -> int:
    base_dir = Path("data")
    encrypted = base_dir / "demo_sensitive.json.encrypted.json"

    if not os.getenv("DATA_ENCRYPTION_KEY"):
        print("DATA_ENCRYPTION_KEY is not set.")
        print("Generate one and export it, e.g. (bash):")
        print(f"  export DATA_ENCRYPTION_KEY='{generate_fernet_key_str()}'")
        print("Then re-run this script.")
        return 2

    payload = build_fake_sensitive_payload()
    plaintext_bytes = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")

    try:
        encrypt_bytes_to_envelope_file(plaintext=plaintext_bytes, encrypted_path=encrypted, base_dir=base_dir)
    except CryptoConfigError as e:
        print(str(e))
        return 2

    print(f"Encrypted (no plaintext written): {encrypted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
