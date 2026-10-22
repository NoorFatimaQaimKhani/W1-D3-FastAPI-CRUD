from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session

from backend.api.core.deps import get_current_user, require_roles
from backend.api.core.permissions import Role
from backend.api.core.redis_client import get_redis
from backend.api.db.connection import get_db
from backend.api.models.user import User
from backend.api.schemas.user import (
    PublicKeyRegister,
    PublicKeyRotationChallenge,
    UserOut,
    UserUpdate,
)
from backend.api.services import user_service

router = APIRouter(prefix="/users", tags=["users"])

admin_only = require_roles(Role.ADMIN)

@router.get("/me", response_model=UserOut)
def read_me(user: User = Depends(get_current_user)):
    return user


@router.put("/me/public-key", response_model=UserOut)
def register_public_key(
    data: PublicKeyRegister,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    r=Depends(get_redis),
):
    """Register a key with password confirmation; rotations also require the old key."""
    return user_service.register_public_key(
        db,
        r,
        user,
        data.public_key_pem,
        data.current_password,
        str(data.rotation_challenge_id) if data.rotation_challenge_id else None,
        data.rotation_signature,
    )


@router.post(
    "/me/public-key/challenge", response_model=PublicKeyRotationChallenge
)
def create_public_key_rotation_challenge(
    user: User = Depends(get_current_user),
    r=Depends(get_redis),
):
    challenge_id, challenge = user_service.create_key_rotation_challenge(r, user)
    return PublicKeyRotationChallenge(challenge_id=challenge_id, challenge=challenge)


# ADMIN only 
@router.get("", response_model=list[UserOut])
def list_users(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    _admin: User = Depends(admin_only),
    db: Session = Depends(get_db),
):
    return user_service.list_users(db, limit, offset)


@router.get("/{user_id}", response_model=UserOut)
def get_user(user_id: int, _admin: User = Depends(admin_only), db: Session = Depends(get_db)):
    return user_service.get_user(db, user_id)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    data: UserUpdate,
    admin: User = Depends(admin_only),
    db: Session = Depends(get_db),
):
    return user_service.update_user(db, admin, user_id, data)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, admin: User = Depends(admin_only), db: Session = Depends(get_db)):
    user_service.delete_user(db, admin, user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
