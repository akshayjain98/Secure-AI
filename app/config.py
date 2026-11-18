"""Application settings, read once from the environment.

Fail-fast: a missing or weak secret raises at startup, not at the first request.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import timedelta

from dotenv import load_dotenv

from app.auth.service import AuthSettings

load_dotenv()

MIN_KEY_BYTES = 32


def parse_jwt_keys(raw: str) -> dict[str, bytes]:
    """"kid1:hex,kid0:hex" -> {kid: key}. The FIRST entry signs; all verify.

    Rotation: prepend a new key, deploy, wait one access-token lifetime,
    then drop the old key.
    """
    keys: dict[str, bytes] = {}
    for part in filter(None, (p.strip() for p in raw.split(","))):
        kid, sep, hexkey = part.partition(":")
        if not sep or not kid or not kid.replace("-", "").replace("_", "").isalnum():
            raise RuntimeError("SECUREAI_JWT_KEYS entries must look like kid:hexkey")
        try:
            key = bytes.fromhex(hexkey)
        except ValueError as exc:
            raise RuntimeError(f"JWT key {kid!r} must be hex-encoded") from exc
        if len(key) < MIN_KEY_BYTES:
            raise RuntimeError(f"JWT key {kid!r} must be at least {MIN_KEY_BYTES} bytes")
        if kid in keys:
            raise RuntimeError(f"duplicate JWT kid {kid!r}")
        keys[kid] = key
    if not keys:
        raise RuntimeError("SECUREAI_JWT_KEYS is empty")
    return keys


@dataclass(frozen=True)
class Settings:
    env: str
    jwt_keys: dict[str, bytes] = field(repr=False)
    token_pepper: bytes = field(repr=False)
    public_url: str = "http://localhost:5173"
    issuer: str = "secureai"
    audience: str = "secureai-api"
    access_ttl: timedelta = timedelta(minutes=10)
    auth: AuthSettings = field(default_factory=AuthSettings)
    # Rate limits: (max requests, window seconds). Per process (see docs §5).
    login_per_ip: tuple[int, int] = (20, 60)
    login_per_email: tuple[int, int] = (10, 900)
    reset_per_ip: tuple[int, int] = (5, 900)
    refresh_per_ip: tuple[int, int] = (60, 60)

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @classmethod
    def from_env(cls) -> Settings:
        env = os.environ.get("SECUREAI_ENV", "development").lower()
        jwt_raw = os.environ.get("SECUREAI_JWT_KEYS")
        if not jwt_raw:
            raise RuntimeError("SECUREAI_JWT_KEYS is not set (kid:$(openssl rand -hex 32))")
        pepper_raw = os.environ.get("SECUREAI_TOKEN_PEPPER")
        if not pepper_raw:
            raise RuntimeError("SECUREAI_TOKEN_PEPPER is not set (openssl rand -hex 32)")
        try:
            pepper = bytes.fromhex(pepper_raw)
        except ValueError as exc:
            raise RuntimeError("SECUREAI_TOKEN_PEPPER must be hex-encoded") from exc
        settings = cls(
            env=env,
            jwt_keys=parse_jwt_keys(jwt_raw),
            token_pepper=pepper,
            public_url=os.environ.get("SECUREAI_PUBLIC_URL", cls.public_url).rstrip("/"),
        )
        if settings.is_production and not settings.public_url.startswith("https://"):
            raise RuntimeError("SECUREAI_PUBLIC_URL must be https in production")
        return settings
