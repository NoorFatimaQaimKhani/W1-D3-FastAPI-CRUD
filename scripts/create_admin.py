
from getpass import getpass

from pydantic import ValidationError

from backend.api import models  # noqa: F401
from backend.api.core.permissions import Role
from backend.api.core.security import hash_password
from backend.api.db.connection import SessionLocal, commit
from backend.api.models.user import User
from backend.api.repositories import user_repository
from backend.api.schemas.auth import RegisterRequest


def main() -> None:
    email = input("Admin email: ").strip()
    password = getpass("Password (min 10 chars): ")
    if password != getpass("Confirm password: "):
        raise SystemExit("Passwords do not match.")

    try:
        data = RegisterRequest(email=email, password=password)
    except ValidationError as exc:
        raise SystemExit(f"Invalid input:\n{exc}")

    with SessionLocal() as db:
        existing = user_repository.get_by_email(db, data.email)
        if existing:
            existing.role = Role.ADMIN.value
            existing.is_active = True
            commit(db)
            print(f"User {data.email} already existed: promoted to ADMIN (password unchanged).")
            return
        admin = User(
            email=data.email,
            hashed_password=hash_password(data.password),
            role=Role.ADMIN.value,
        )
        user_repository.add(db, admin)
        commit(db)
        print(f"Admin {data.email} created.")


if __name__ == "__main__":
    main()