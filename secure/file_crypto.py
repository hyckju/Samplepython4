from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .crypto import Fernet, decrypt_to_bytes, encrypt_bytes, load_fernet_from_env


class UnsafePathError(ValueError):
    pass


def _ensure_under_base(path: Path, base_dir: Path) -> Path:
    base = base_dir.resolve()
    candidate = path.resolve()

    try:
        candidate.relative_to(base)
    except ValueError as e:
        raise UnsafePathError("refusing to write outside base_dir") from e

    return candidate


@dataclass(frozen=True)
class EncryptedFileEnvelope:
    version: int
    alg: str
    created_at: float
    ciphertext: str


def encrypt_bytes_to_envelope_file(
    *,
    plaintext: bytes,
    encrypted_path: Path,
    base_dir: Path,
    fernet: Fernet | None = None,
) -> None:
    """Encrypt in-memory bytes directly to an envelope JSON file.

    This avoids writing the plaintext to disk.
    """

    encrypted_real = _ensure_under_base(encrypted_path, base_dir)
    f = fernet or load_fernet_from_env()

    env = EncryptedFileEnvelope(
        version=1,
        alg="fernet",
        created_at=time.time(),
        ciphertext=encrypt_bytes(plaintext, fernet=f),
    )

    encrypted_real.parent.mkdir(parents=True, exist_ok=True)
    encrypted_real.write_text(json.dumps(env.__dict__, ensure_ascii=False, indent=2), encoding="utf-8")

    if os.name == "posix":
        try:
            os.chmod(encrypted_real, 0o600)
        except Exception:
            pass


def decrypt_envelope_file_to_bytes(
    *,
    encrypted_path: Path,
    base_dir: Path,
    fernet: Fernet | None = None,
) -> bytes:
    """Decrypt an envelope JSON file and return plaintext bytes."""

    encrypted_real = _ensure_under_base(encrypted_path, base_dir)
    f = fernet or load_fernet_from_env()

    raw = encrypted_real.read_text(encoding="utf-8")
    obj: Any = json.loads(raw)

    if not isinstance(obj, dict) or obj.get("alg") != "fernet" or "ciphertext" not in obj:
        raise ValueError("invalid envelope format")

    return decrypt_to_bytes(str(obj["ciphertext"]), fernet=f)


def encrypt_file(
    *,
    plaintext_path: Path,
    encrypted_path: Path,
    base_dir: Path,
    fernet: Fernet | None = None,
) -> None:
    """Encrypt a file to a small JSON envelope.

    - Prevents directory traversal by forcing outputs under base_dir.
    - Uses DATA_ENCRYPTION_KEY from env (unless fernet is passed).
    - Best-effort restrictive permissions on POSIX.
    """

    plaintext_real = _ensure_under_base(plaintext_path, base_dir)
    encrypted_real = _ensure_under_base(encrypted_path, base_dir)

    f = fernet or load_fernet_from_env()

    data = plaintext_real.read_bytes()
    env = EncryptedFileEnvelope(
        version=1,
        alg="fernet",
        created_at=time.time(),
        ciphertext=encrypt_bytes(data, fernet=f),
    )

    encrypted_real.parent.mkdir(parents=True, exist_ok=True)
    encrypted_real.write_text(json.dumps(env.__dict__, ensure_ascii=False, indent=2), encoding="utf-8")

    if os.name == "posix":
        try:
            os.chmod(encrypted_real, 0o600)
        except Exception:
            pass


def decrypt_file(
    *,
    encrypted_path: Path,
    decrypted_path: Path,
    base_dir: Path,
    fernet: Fernet | None = None,
) -> None:
    encrypted_real = _ensure_under_base(encrypted_path, base_dir)
    decrypted_real = _ensure_under_base(decrypted_path, base_dir)

    f = fernet or load_fernet_from_env()

    raw = encrypted_real.read_text(encoding="utf-8")
    obj: Any = json.loads(raw)

    if not isinstance(obj, dict) or obj.get("alg") != "fernet" or "ciphertext" not in obj:
        raise ValueError("invalid envelope format")

    plaintext = decrypt_to_bytes(str(obj["ciphertext"]), fernet=f)

    decrypted_real.parent.mkdir(parents=True, exist_ok=True)
    decrypted_real.write_bytes(plaintext)

    if os.name == "posix":
        try:
            os.chmod(decrypted_real, 0o600)
        except Exception:
            pass
