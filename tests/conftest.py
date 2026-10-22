import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_key_dir = Path(tempfile.mkdtemp(prefix="jwt-test-keys-"))
_test_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
(_key_dir / "private.pem").write_bytes(
    _test_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)
(_key_dir / "public.pem").write_bytes(
    _test_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
)
os.environ["JWT_PRIVATE_KEY_PATH"] = str(_key_dir / "private.pem")
os.environ["JWT_PUBLIC_KEY_PATH"] = str(_key_dir / "public.pem")

from dataclasses import dataclass  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from backend.api import models  # noqa: E402, F401
from backend.api.core.config import settings  # noqa: E402
from backend.api.core.redis_client import get_redis  # noqa: E402
from backend.api.core.security import hash_password  # noqa: E402
from backend.api.db.connection import get_db  # noqa: E402
from backend.api.main import app  # noqa: E402
from backend.api.models.user import User  # noqa: E402
from client.crypto import decrypt_envelope, generate_keypair  # noqa: E402

PASSWORD = "correct-horse-battery"


def _validate_test_services() -> None:
    database_url = make_url(settings.database_url)
    if (
        database_url.get_backend_name() != "postgresql"
        or not (database_url.database or "").endswith("_test")
        or database_url.host not in {"localhost", "127.0.0.1", "::1"}
    ):
        raise RuntimeError(
            "Tests require a local PostgreSQL database whose name ends in _test"
        )

    redis_url = make_url(settings.redis_url)
    if (
        redis_url.host not in {"localhost", "127.0.0.1", "::1"}
        or not redis_url.database
        or int(redis_url.database) == 0
    ):
        raise RuntimeError(
            "Tests require a local Redis instance using a nonzero database index"
        )


@pytest.fixture(scope="session", autouse=True)
def apply_test_migrations():
    _validate_test_services()
    from alembic import command
    from alembic.config import Config

    command.upgrade(Config("alembic.ini"), "head")


@pytest.fixture()
def session_factory():
    engine = create_engine(settings.database_url, pool_pre_ping=True)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "TRUNCATE TABLE customers, users RESTART IDENTITY CASCADE"
        )
    yield sessionmaker(bind=engine, autoflush=False)
    engine.dispose()


@pytest.fixture()
def redis_client():
    import redis

    client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    client.flushdb()
    yield client
    client.flushdb()
    client.close()


@pytest.fixture()
def client(session_factory, redis_client):
    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis] = lambda: redis_client
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture()
def make_user(session_factory):
    def _make(email: str, role: str = "USER", active: bool = True) -> int:
        with session_factory() as db:
            user = User(
                email=email,
                hashed_password=hash_password(PASSWORD),
                role=role,
                is_active=active,
            )
            db.add(user)
            db.commit()
            return user.id

    return _make


def login(client: TestClient, email: str, password: str = PASSWORD) -> str:
    r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@dataclass
class Actor:
    id: int
    email: str
    headers: dict
    private_pem: bytes
    public_pem: str

    def decrypt(self, response):
        assert response.status_code in (200, 201), response.text
        return decrypt_envelope(response.json(), self.private_pem)


@pytest.fixture()
def actors(client, make_user):
    """alice & bob (USER), mia (MANAGER), ada (ADMIN): each logged in with a registered key."""
    result = {}
    for name, role in [("alice", "USER"), ("bob", "USER"), ("mia", "MANAGER"), ("ada", "ADMIN")]:
        email = f"{name}@corp.com"
        user_id = make_user(email, role)
        headers = {"Authorization": f"Bearer {login(client, email)}"}
        private_pem, public_pem = generate_keypair()
        r = client.put(
            "/api/v1/users/me/public-key",
            headers=headers,
            json={"public_key_pem": public_pem, "current_password": PASSWORD},
        )
        assert r.status_code == 200, r.text
        result[name] = Actor(user_id, email, headers, private_pem, public_pem)
    return result


def create_customer(client, actor: Actor, name: str = "Test Customer", **extra) -> dict:
    r = client.post(
        "/api/v1/customers", headers=actor.headers, json={"full_name": name, **extra}
    )
    return actor.decrypt(r)