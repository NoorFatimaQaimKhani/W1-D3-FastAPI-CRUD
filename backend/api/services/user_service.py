from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend.api.core.crypto import InvalidPublicKey, load_rsa_public_key, public_key_fingerprint
from backend.api.core.permissions import Role
from backend.api.db.connection import commit
from backend.api.models.user import User
from backend.api.repositories import customer_repository, user_repository
from backend.api.schemas.user import UserUpdate


def _get_or_404(db: Session, user_id: int) -> User:
    user = user_repository.get_by_id(db, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return user


def get_user(db: Session, user_id: int) -> User:
    return _get_or_404(db, user_id)


def list_users(db: Session, limit: int, offset: int) -> list[User]:
    return user_repository.list_users(db, limit, offset)


def update_user(db: Session, admin: User, user_id: int, data: UserUpdate) -> User:
    target = _get_or_404(db, user_id)

    if target.id == admin.id and (
        (data.role is not None and data.role != Role.ADMIN) or data.is_active is False
    ):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Admins cannot demote or deactivate themselves"
        )

    if data.role is not None:
        target.role = data.role.value
    if data.is_active is not None:
        target.is_active = data.is_active
    commit(db)
    db.refresh(target)
    return target


def delete_user(db: Session, admin: User, user_id: int) -> None:
    target = _get_or_404(db, user_id)
    if target.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Admins cannot delete themselves")
    if customer_repository.count_by_owner(db, target.id) > 0:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "User still owns customer records. Delete them first, or deactivate the user instead.",
        )
    user_repository.delete(db, target)
    commit(db)


def register_public_key(db: Session, user: User, pem: str) -> User:
    try:
        key = load_rsa_public_key(pem)
    except InvalidPublicKey as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
    user.public_key_pem = pem
    user.public_key_fingerprint = public_key_fingerprint(key)
    commit(db)
    db.refresh(user)
    return user
