from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.api.core.config import settings
from backend.api.core.permissions import Role
from backend.api.core.rate_limit import login_limiter
from backend.api.core.security import (
    DUMMY_HASH,
    create_access_token,
    hash_password,
    verify_password,
)
from backend.api.db.connection import commit
from backend.api.models.user import User
from backend.api.repositories import token_repository, user_repository
from backend.api.schemas.auth import RegisterRequest, TokenResponse


def register_user(db: Session, data: RegisterRequest) -> None:

    hashed = hash_password(data.password)

    if user_repository.get_by_email(db, data.email):
        return 

    user = User(email=data.email, hashed_password=hashed, role=Role.USER.value)
    try:
        user_repository.add(db, user)
        commit(db)
    except IntegrityError:
        db.rollback()


def login(db: Session, r, email: str, password: str, client_ip: str) -> TokenResponse:
    limiter_key = f"{client_ip}:{email}"
    if login_limiter.is_blocked(r, limiter_key):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed login attempts. Try again later.",
        )

    user = user_repository.get_by_email(db, email)
    password_ok = verify_password(password, user.hashed_password if user else DUMMY_HASH)

    if user is None or not password_ok or not user.is_active:
        login_limiter.record_failure(r, limiter_key)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    login_limiter.reset(r, limiter_key)
    token, _expires = create_access_token(user.id)
    return TokenResponse(
        access_token=token, expires_in=settings.access_token_expire_minutes * 60
    )


def logout(r, jti: str, exp_timestamp: int) -> None:
    token_repository.revoke(r, jti, exp_timestamp)