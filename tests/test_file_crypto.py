import json
import os
import unittest
from pathlib import Path

from cryptography.fernet import Fernet

from secure.file_crypto import (
    UnsafePathError,
    decrypt_envelope_file_to_bytes,
    decrypt_file,
    encrypt_bytes_to_envelope_file,
    encrypt_file,
)


class TestFileCrypto(unittest.TestCase):
    def setUp(self):
        self.base_dir = Path("data")
        self.base_dir.mkdir(parents=True, exist_ok=True)

        self.key = Fernet.generate_key().decode("utf-8")
        os.environ["DATA_ENCRYPTION_KEY"] = self.key

        self.plain = self.base_dir / "_test_plain.json"
        self.enc = self.base_dir / "_test_plain.json.encrypted.json"
        self.dec = self.base_dir / "_test_plain.json.decrypted.json"

        self.plain.write_text(json.dumps({"hello": "world"}), encoding="utf-8")

    def tearDown(self):
        for p in (self.plain, self.enc, self.dec):
            try:
                if p.exists():
                    p.unlink()
            except Exception:
                pass

    def test_roundtrip_encrypt_decrypt(self):
        encrypt_file(plaintext_path=self.plain, encrypted_path=self.enc, base_dir=self.base_dir)
        self.assertTrue(self.enc.exists())

        decrypt_file(encrypted_path=self.enc, decrypted_path=self.dec, base_dir=self.base_dir)
        self.assertTrue(self.dec.exists())

        self.assertEqual(self.plain.read_text(encoding="utf-8"), self.dec.read_text(encoding="utf-8"))

    def test_roundtrip_encrypt_bytes_decrypt_bytes(self):
        enc = self.base_dir / "_test_bytes.encrypted.json"
        try:
            payload = b"hello-bytes"
            encrypt_bytes_to_envelope_file(plaintext=payload, encrypted_path=enc, base_dir=self.base_dir)
            out = decrypt_envelope_file_to_bytes(encrypted_path=enc, base_dir=self.base_dir)
            self.assertEqual(payload, out)
        finally:
            try:
                if enc.exists():
                    enc.unlink()
            except Exception:
                pass

    def test_refuse_write_outside_base(self):
        outside = Path("..").resolve() / "evil.json"
        with self.assertRaises(UnsafePathError):
            encrypt_file(plaintext_path=self.plain, encrypted_path=outside, base_dir=self.base_dir)


if __name__ == "__main__":
    unittest.main()
