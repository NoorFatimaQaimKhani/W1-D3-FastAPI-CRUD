
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from backend.api.core.permissions import Role
from backend.api.core.redis_client import get_redis
from backend.api.core.security import decode_access_token
from backend.api.db.connection import get_db
from backend.api.models.user import User
from backend.api.repositories import token_repository, user_repository

bearer_scheme = HTTPBearer(auto_error=False)  


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Bearer"}
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
    r=Depends(get_redis),
) -> User:
#    If Redis is down the deny-list cannot be checked, so the request FAILS (503) instead of letting the token through.
    if credentials is None:
        raise _unauthorized()
    try:
        payload = decode_access_token(credentials.credentials)
    except jwt.InvalidTokenError:
        raise _unauthorized("Invalid or expired token")

    if token_repository.is_revoked(r, payload["jti"]):
        raise _unauthorized("Token has been revoked")

    try:
        user_id = int(payload["sub"])
    except ValueError:
        raise _unauthorized("Invalid or expired token")

    user = user_repository.get_by_id(db, user_id)
    if user is None or not user.is_active:
        raise _unauthorized("Invalid or expired token")
    return user


def require_roles(*allowed: Role):
    allowed_values = {r.value for r in allowed}

    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_values:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user

    return checker


def get_user_with_public_key(user: User = Depends(get_current_user)) -> User:
    if not user.public_key_pem:
        raise HTTPException(
            status.HTTP_428_PRECONDITION_REQUIRED,
            "Register an RSA public key via PUT /api/v1/users/me/public-key first",
        )
    return user