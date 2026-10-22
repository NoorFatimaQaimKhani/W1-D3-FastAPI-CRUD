from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.api.core.deps import bearer_scheme, get_current_user
from backend.api.core.redis_client import get_redis
from backend.api.core.security import decode_access_token
from backend.api.db.connection import get_db
from backend.api.models.user import User
from backend.api.schemas.auth import (
    LoginRequest,
    RegisterAccepted,
    RegisterRequest,
    TokenResponse,
)
from backend.api.services import auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=RegisterAccepted, status_code=status.HTTP_202_ACCEPTED)
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    auth_service.register_user(db, data)
    return RegisterAccepted()  # same body whether or not the email already existed


@router.post("/login", response_model=TokenResponse)
def login(
    data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    r=Depends(get_redis),
):
    client_ip = request.client.host if request.client else "unknown"
    return auth_service.login(db, r, data.email, data.password, client_ip)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    _user: User = Depends(get_current_user),  # proves the token is currently valid
    r=Depends(get_redis),
):
    payload = decode_access_token(credentials.credentials)
    auth_service.logout(r, payload["jti"], payload["exp"])
    return Response(status_code=status.HTTP_204_NO_CONTENT)