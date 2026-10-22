import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from backend.api.core.config import settings

JWT_ALGORITHM = "RS256"

# Argon2.
_password_hash = PasswordHash((Argon2Hasher(),))

DUMMY_HASH = _password_hash.hash("not-a-real-password-just-for-timing")


def hash_password(plain: str) -> str:
    return _password_hash.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _password_hash.verify(plain, hashed)


@lru_cache(maxsize=1)
def _private_key() -> bytes:
    return Path(settings.jwt_private_key_path).read_bytes()


@lru_cache(maxsize=1)
def _public_key() -> bytes:
    return Path(settings.jwt_public_key_path).read_bytes()


def create_access_token(user_id: int) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": expires,
        "jti": uuid.uuid4().hex,  # unique id, lets us revoke on logout
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }
    token = jwt.encode(payload, _private_key(), algorithm=JWT_ALGORITHM)
    return token, expires


def decode_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        _public_key(),
        algorithms=[JWT_ALGORITHM],  # pinned: blocks "alg: none" and HS256 key-confusion tricks
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        options={"require": ["exp", "iat", "sub", "jti", "iss", "aud"]},
    )