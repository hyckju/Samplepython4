from __future__ import annotations

import json
import secrets
import time
from pathlib import Path


def _token(nbytes: int = 12) -> str:
    return secrets.token_urlsafe(nbytes)


def build_fake_sensitive_payload() -> dict:
    """Return a payload that *looks like* sensitive data but is intentionally fake.

    Notes:
    - Includes broken/invalid patterns to avoid accidental real-world validity.
    - Uses example.com domain and documentation IP ranges.
    """

    now = int(time.time())

    return {
        "disclaimer": "FAKE DATA ONLY. Intentionally invalid / non-real identifiers.",
        "generated_at": now,
        "person": {
            "full_name": "홍길동(FAKE)",
            "email": f"demo+{_token(6)}@example.com",
            "phone_like": "010-0000-0000",
            "address_like": "서울특별시 어딘가 123 (FAKE)",
        },
        "identifiers_like": {
            # Korean RRN-like shape: YYMMDD-XXXXXXX, but intentionally broken.
            "korean_rrn_like": "991332-123456X",
            # Passport-like: letters+digits, but includes invalid marker.
            "passport_like": "M0000000X(FAKE)",
            # Driver license-like placeholder.
            "driver_license_like": "DL-12-345678-90X",
        },
        "payment_like": {
            # Card-like formatting but with a non-digit to break numeric validation/Luhn.
            "card_number_like": "4111-1111-1111-111X",
            "card_expiry_like": "13/99",
            "card_cvv_like": "12X",
            "bank_account_like": "110-000-000000X",
        },
        "network_like": {
            "public_ip_like": "203.0.113.10",
            "device_id_like": f"dev_{_token(10)}",
        },
        "notes": [
            "All fields are synthetic and intentionally invalid.",
            "Do not replace these with real personal data in a repo.",
        ],
    }


def main() -> int:
    out_path = Path("data/demo_sensitive.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    payload = build_fake_sensitive_payload()
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Wrote: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
