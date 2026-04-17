import base64
import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any, Literal

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, SecretStr
from starlette.middleware.base import BaseHTTPMiddleware

# -----------------------------
# Configuration (env-driven)
# -----------------------------

def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "t", "yes", "y", "on"}


def _env_csv(name: str) -> list[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


APP_NAME = os.getenv("APP_NAME", "secure-fastapi")
ENVIRONMENT = os.getenv("ENVIRONMENT", "production").strip().lower()

ENABLE_DOCS = _env_bool("ENABLE_DOCS", default=False)
ALLOW_CORS_ORIGINS = _env_csv("CORS_ALLOW_ORIGINS")

ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN")  # optional; if unset, protected endpoints return 503
DATA_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY")  # optional; required to store PII-like secrets

RATE_LIMIT_RPS = float(os.getenv("RATE_LIMIT_RPS", "5"))  # requests per second
RATE_LIMIT_BURST = int(os.getenv("RATE_LIMIT_BURST", "10"))

MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", "65536"))  # bytes; enforced via Content-Length header


# -----------------------------
# Security helpers
# -----------------------------

def _constant_time_equals(a: str, b: str) -> bool:
    # Avoid subtle timing leaks on token checks.
    try:
        import secrets

        return secrets.compare_digest(a, b)
    except Exception:
        # Fallback: still avoid obvious early-return patterns.
        if len(a) != len(b):
            return False
        out = 0
        for x, y in zip(a.encode("utf-8"), b.encode("utf-8"), strict=False):
            out |= x ^ y
        return out == 0


def _get_fernet() -> Fernet:
    if not DATA_ENCRYPTION_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="DATA_ENCRYPTION_KEY is not configured",
        )

    key = DATA_ENCRYPTION_KEY.strip().encode("utf-8")
    try:
        # Accept either a proper Fernet key, or a raw 32-byte base64url key string.
        Fernet(key)
        return Fernet(key)
    except Exception:
        # Helpful second attempt if user provided raw 32 bytes (not base64).
        try:
            raw = key
            if len(raw) == 32:
                return Fernet(base64.urlsafe_b64encode(raw))
        except Exception:
            pass

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid DATA_ENCRYPTION_KEY format (must be Fernet key)",
    )


# -----------------------------
# Middleware
# -----------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        # Avoid caching of API responses that may contain sensitive metadata.
        response.headers.setdefault("Cache-Control", "no-store")
        return response


@dataclass
class _Bucket:
    tokens: float
    last: float


class SimpleRateLimitMiddleware(BaseHTTPMiddleware):
    """A small, in-memory token bucket limiter.

    Not a replacement for edge rate-limiting, but helps reduce brute force and noisy clients.
    """

    def __init__(self, app: Any, rps: float, burst: int):
        super().__init__(app)
        self._rps = max(rps, 0.1)
        self._burst = max(burst, 1)
        self._buckets: dict[str, _Bucket] = {}

    async def dispatch(self, request: Request, call_next):
        client = request.client.host if request.client else "unknown"
        now = time.monotonic()

        bucket = self._buckets.get(client)
        if bucket is None:
            bucket = _Bucket(tokens=float(self._burst), last=now)
            self._buckets[client] = bucket

        elapsed = max(0.0, now - bucket.last)
        bucket.last = now
        bucket.tokens = min(float(self._burst), bucket.tokens + elapsed * self._rps)

        if bucket.tokens < 1.0:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")

        bucket.tokens -= 1.0
        return await call_next(request)


class ContentLengthLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > MAX_CONTENT_LENGTH:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="request too large",
                    )
            except ValueError:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid content-length")
        return await call_next(request)


# -----------------------------
# Models
# -----------------------------

SecretKind = Literal["password", "pii"]


class SecretCreate(BaseModel):
    label: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    kind: SecretKind
    # Keep value out of repr/logging.
    value: SecretStr = Field(min_length=8, max_length=4096)


class SecretCreated(BaseModel):
    id: str


class SecretMeta(BaseModel):
    id: str
    label: str
    kind: SecretKind
    created_at: float


class SeedItem(BaseModel):
    id: str
    label: str
    kind: SecretKind


class SeedResult(BaseModel):
    created: list[SeedItem]
    skipped_pii: bool = False


# -----------------------------
# Storage (in-memory demo)
# -----------------------------

try:
    from passlib.context import CryptContext

    _pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")
except Exception:
    _pwd_ctx = None


class _StoredSecret(BaseModel):
    id: str
    label: str
    kind: SecretKind
    created_at: float
    value_protected: str


_STORE: dict[str, _StoredSecret] = {}


# -----------------------------
# Auth dependency
# -----------------------------

def require_admin(request: Request) -> None:
    if not ADMIN_API_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ADMIN_API_TOKEN is not configured",
        )

    auth = request.headers.get("authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")

    token = auth.split(" ", 1)[1].strip()
    if not _constant_time_equals(token, ADMIN_API_TOKEN):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")


# -----------------------------
# App
# -----------------------------

app = FastAPI(
    title=APP_NAME,
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(SimpleRateLimitMiddleware, rps=RATE_LIMIT_RPS, burst=RATE_LIMIT_BURST)
app.add_middleware(ContentLengthLimitMiddleware)

if ALLOW_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOW_CORS_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )


@app.get("/healthz")
async def healthz():
    # Keep health output non-sensitive.
    return {"ok": True, "env": ENVIRONMENT}


def _store_secret(*, label: str, kind: SecretKind, raw_value: str) -> str:
    sid = str(uuid.uuid4())
    now = time.time()

    if kind == "password":
        if _pwd_ctx is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Password hashing backend is not available",
            )
        protected = _pwd_ctx.hash(raw_value)
    else:
        f = _get_fernet()
        protected = f.encrypt(raw_value.encode("utf-8")).decode("utf-8")

    _STORE[sid] = _StoredSecret(
        id=sid,
        label=label,
        kind=kind,
        created_at=now,
        value_protected=protected,
    )

    return sid


@app.post("/v1/secrets", response_model=SecretCreated, dependencies=[Depends(require_admin)])
async def create_secret(payload: SecretCreate):
    sid = _store_secret(
        label=payload.label,
        kind=payload.kind,
        raw_value=payload.value.get_secret_value(),
    )
    return SecretCreated(id=sid)


@app.post("/v1/demo/seed", response_model=SeedResult, dependencies=[Depends(require_admin)])
async def seed_demo_secrets():
    """Create clearly-labeled demo secrets.

    - Values are generated at runtime (no hardcoded secrets)
    - Password-kind secrets are stored as Argon2 hashes
    - PII-kind secrets are encrypted-at-rest and require DATA_ENCRYPTION_KEY
    """

    created: list[SeedItem] = []

    def _testnet_ip() -> str:
        prefixes = ("192.0.2", "198.51.100", "203.0.113")
        prefix = prefixes[secrets.randbelow(len(prefixes))]
        last = secrets.randbelow(254) + 1
        return f"{prefix}.{last}"

    # Password-like secrets (stored hashed)
    for label in (
        "root_password",
        "admin_password",
        "break_glass_password",
        "db_admin_password",
    ):
        raw = "Demo-" + secrets.token_urlsafe(24)
        sid = _store_secret(label=label, kind="password", raw_value=raw)
        created.append(SeedItem(id=sid, label=label, kind="password"))

    # PII-like secrets (stored encrypted)
    skipped_pii = False
    if DATA_ENCRYPTION_KEY:
        host_ip = _testnet_ip()

        root_bundle = json.dumps(
            {
                "account": "root",
                "uid": 0,
                "gid": 0,
                "ssh_host": host_ip,
                "ssh_port": 22,
                "notes": "FAKE demo only; do not use in production",
            },
            separators=(",", ":"),
        )
        sid = _store_secret(label="root_access_bundle", kind="pii", raw_value=root_bundle)
        created.append(SeedItem(id=sid, label="root_access_bundle", kind="pii"))

        inventory = json.dumps(
            {
                "mgmt_ip": host_ip,
                "host_fingerprint": secrets.token_hex(16),
                "asset_tag": "DEMO-ASSET-" + secrets.token_hex(4).upper(),
            },
            separators=(",", ":"),
        )
        sid = _store_secret(label="server_inventory", kind="pii", raw_value=inventory)
        created.append(SeedItem(id=sid, label="server_inventory", kind="pii"))

        api_token_bundle = json.dumps(
            {
                "service": "demo-service",
                "token": "demo_tok_" + secrets.token_urlsafe(32),
                "scopes": ["read", "write"],
                "issued_at": int(time.time()),
            },
            separators=(",", ":"),
        )
        sid = _store_secret(label="api_token", kind="pii", raw_value=api_token_bundle)
        created.append(SeedItem(id=sid, label="api_token", kind="pii"))

        # Intentionally NOT a real key format (avoid confusion and accidental reuse).
        fake_key_material = "FAKE-SSH-PRIVATE-KEY v1\n" + json.dumps(
            {
                "type": "ed25519",
                "kid": "demo-" + secrets.token_hex(8),
                "created_at": int(time.time()),
                "material": secrets.token_urlsafe(96),
                "note": "FAKE demo only; not a valid private key",
            },
            separators=(",", ":"),
        )
        sid = _store_secret(label="ssh_private_key", kind="pii", raw_value=fake_key_material)
        created.append(SeedItem(id=sid, label="ssh_private_key", kind="pii"))
    else:
        skipped_pii = True

    return SeedResult(created=created, skipped_pii=skipped_pii)


@app.get("/v1/secrets/{secret_id}", response_model=SecretMeta, dependencies=[Depends(require_admin)])
async def get_secret_meta(secret_id: str):
    item = _STORE.get(secret_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return SecretMeta(id=item.id, label=item.label, kind=item.kind, created_at=item.created_at)


@app.post("/v1/secrets/{secret_id}/verify-password", dependencies=[Depends(require_admin)])
async def verify_password(secret_id: str, candidate: SecretStr):
    item = _STORE.get(secret_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if item.kind != "password":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="secret is not a password")
    if _pwd_ctx is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Password backend unavailable")

    ok = _pwd_ctx.verify(candidate.get_secret_value(), item.value_protected)
    return {"ok": bool(ok)}


@app.get("/v1/secrets/{secret_id}/reveal", dependencies=[Depends(require_admin)])
async def reveal_pii(secret_id: str):
    """Reveal is intentionally restricted to PII-kind secrets and requires encryption key.

    For most systems, you should avoid implementing reveal endpoints.
    This exists only to demonstrate encryption-at-rest.
    """

    item = _STORE.get(secret_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if item.kind != "pii":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="secret is not PII")

    f = _get_fernet()
    try:
        raw = f.decrypt(item.value_protected.encode("utf-8"))
    except InvalidToken:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="decryption failed")

    # Never cache responses that contain sensitive data.
    return Response(content=raw, media_type="text/plain", headers={"Cache-Control": "no-store"})


if __name__ == "__main__":
    # Local dev only. Production should run via an ASGI server.
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, log_level="info")
