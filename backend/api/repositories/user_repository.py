from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.models.user import User


def get_by_id(db: Session, user_id: int) -> User | None:
    return db.get(User, user_id)


def get_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email.lower()))


def list_users(db: Session, limit: int, offset: int) -> list[User]:
    stmt = select(User).order_by(User.id).limit(limit).offset(offset)
    return list(db.scalars(stmt))


def add(db: Session, user: User) -> User:
    db.add(user)
    db.flush()
    return user


def delete(db: Session, user: User) -> None:
    db.delete(user)
