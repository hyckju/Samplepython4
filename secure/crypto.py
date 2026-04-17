from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken


class CryptoConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class FernetConfig:
    env_var_name: str = "DATA_ENCRYPTION_KEY"


def generate_fernet_key_str() -> str:
    """Generate a new Fernet key as a UTF-8 string."""

    return Fernet.generate_key().decode("utf-8")


def load_fernet_from_env(config: FernetConfig | None = None) -> Fernet:
    """Load Fernet instance from an environment variable.

    Accepts either:
    - a standard Fernet base64url key
    - or raw 32 bytes (will be base64url-encoded)

    Never falls back to a hardcoded key.
    """

    cfg = config or FernetConfig()
    raw = os.getenv(cfg.env_var_name)
    if not raw or not raw.strip():
        raise CryptoConfigError(f"{cfg.env_var_name} is not configured")

    key_bytes = raw.strip().encode("utf-8")

    # First try: user provided a real Fernet key.
    try:
        return Fernet(key_bytes)
    except Exception:
        pass

    # Second try: user provided raw 32 bytes (rare, but helpful).
    try:
        if len(key_bytes) == 32:
            return Fernet(base64.urlsafe_b64encode(key_bytes))
    except Exception:
        pass

    raise CryptoConfigError(f"Invalid {cfg.env_var_name} format (must be Fernet key)")


def encrypt_bytes(data: bytes, *, fernet: Fernet) -> str:
    """Encrypt bytes and return Fernet ciphertext (base64url text)."""

    return fernet.encrypt(data).decode("utf-8")


def decrypt_to_bytes(ciphertext: str, *, fernet: Fernet) -> bytes:
    """Decrypt Fernet ciphertext string back to bytes."""

    try:
        return fernet.decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as e:
        raise ValueError("decryption failed (bad key or corrupted ciphertext)") from e
