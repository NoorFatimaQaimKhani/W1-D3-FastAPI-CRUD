from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from redis.exceptions import ConnectionError as RedisConnectionError

from backend.api.core.config import settings
from backend.api.core.redis_client import get_redis
from backend.api.main import app
from backend.api.models.user import User
from backend.api.repositories import token_repository
from tests.conftest import PASSWORD, login

API = "/api/v1"

PRIVATE_KEY = Path(settings.jwt_private_key_path).read_bytes()
PUBLIC_KEY = Path(settings.jwt_public_key_path).read_bytes()


def _register(client, email, password=PASSWORD):
    return client.post(f"{API}/auth/register", json={"email": email, "password": password})


# ---------- registration ----------
def test_register_creates_plain_user_with_neutral_response(client, session_factory):
    r = _register(client, "New@Corp.com")
    assert r.status_code == 202
    assert set(r.json()) == {"detail"}  
    with session_factory() as db:
        user = db.query(User).filter_by(email="new@corp.com").one()  # email was normalised
        assert user.role == "USER"
    assert login(client, "new@corp.com")  


def test_register_cannot_choose_role(client):
    r = client.post(
        f"{API}/auth/register",
        json={"email": "evil@corp.com", "password": PASSWORD, "role": "ADMIN"},
    )
    assert r.status_code == 422


def test_register_rejects_weak_input(client):
    assert _register(client, "a@corp.com", "short").status_code == 422
    assert _register(client, "not-an-email").status_code == 422


def test_register_does_not_reveal_existing_emails(client, session_factory):
    first = _register(client, "dup@corp.com")
    second = _register(client, "DUP@corp.com", "another-long-password")  # same email, new password
    assert first.status_code == second.status_code == 202
    assert first.json() == second.json()

    with session_factory() as db:
        assert db.query(User).filter_by(email="dup@corp.com").count() == 1

    assert login(client, "dup@corp.com")
    r = client.post(
        f"{API}/auth/login", json={"email": "dup@corp.com", "password": "another-long-password"}
    )
    assert r.status_code == 401


def test_password_is_stored_as_argon2id_hash(client, session_factory):
    _register(client, "h@corp.com")
    with session_factory() as db:
        stored = db.query(User).filter_by(email="h@corp.com").one().hashed_password
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


def test_login_returns_rs256_jwt_with_expected_claims(client, make_user):
    make_user("u@corp.com")
    token = login(client, "u@corp.com")
    assert jwt.get_unverified_header(token)["alg"] == "RS256"
    claims = jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=["RS256"],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )
    assert {"sub", "exp", "iat", "jti", "iss", "aud"} <= claims.keys()
    assert "role" not in claims  


def test_login_failures_are_indistinguishable(client, make_user):
    make_user("u@corp.com")
    wrong_pw = client.post(f"{API}/auth/login", json={"email": "u@corp.com", "password": "nope-nope-nope"})
    unknown = client.post(f"{API}/auth/login", json={"email": "ghost@corp.com", "password": "nope-nope-nope"})
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json() == unknown.json()


def test_missing_garbage_expired_and_forged_tokens_are_rejected(client, make_user):
    uid = make_user("u@corp.com")
    assert client.get(f"{API}/users/me").status_code == 401
    assert client.get(f"{API}/users/me", headers={"Authorization": "Bearer garbage"}).status_code == 401

    other_private = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    def forge(key=PRIVATE_KEY, alg="RS256", exp_delta=timedelta(minutes=5), **overrides):
        now = datetime.now(timezone.utc)
        claims = {
            "sub": str(uid), "iat": now, "exp": now + exp_delta, "jti": "abc123",
            "iss": settings.jwt_issuer, "aud": settings.jwt_audience,
        }
        claims.update(overrides)
        return jwt.encode(claims, key, algorithm=alg)

    def status_for(token):
        return client.get(f"{API}/users/me", headers={"Authorization": f"Bearer {token}"}).status_code

    assert status_for(forge()) == 200  
    assert status_for(forge(exp_delta=timedelta(minutes=-5))) == 401  
    assert status_for(forge(key=other_private)) == 401 
    assert status_for(forge(aud="someone-else")) == 401  
    assert status_for(forge(iss="someone-else")) == 401  
    assert status_for(forge(key="a-shared-secret-of-sufficient-length-123", alg="HS256")) == 401  
    unsigned = jwt.encode({"sub": str(uid)}, key=None, algorithm="none")
    assert status_for(unsigned) == 401  


def test_logout_revokes_the_token(client, make_user):
    make_user("u@corp.com")
    headers = {"Authorization": f"Bearer {login(client, 'u@corp.com')}"}
    assert client.get(f"{API}/users/me", headers=headers).status_code == 200
    assert client.post(f"{API}/auth/logout", headers=headers).status_code == 204
    assert client.get(f"{API}/users/me", headers=headers).status_code == 401
    assert client.post(f"{API}/auth/logout", headers=headers).status_code == 401


def test_revoked_entry_expires_with_the_token(client, make_user, fake_redis):
    make_user("u@corp.com")
    token = login(client, "u@corp.com")
    headers = {"Authorization": f"Bearer {token}"}
    assert client.post(f"{API}/auth/logout", headers=headers).status_code == 204

    jti = jwt.decode(
        token, PUBLIC_KEY, algorithms=["RS256"],
        audience=settings.jwt_audience, issuer=settings.jwt_issuer,
    )["jti"]
    ttl = fake_redis.ttl(token_repository.key_for(jti))
    assert 0 < ttl <= settings.access_token_expire_minutes * 60  # self-deletes with the token


class _BrokenRedis:
    def __getattr__(self, name):
        def fail(*args, **kwargs):
            raise RedisConnectionError("redis is down")

        return fail


def test_redis_outage_fails_closed(client, make_user):
    make_user("u@corp.com")
    headers = {"Authorization": f"Bearer {login(client, 'u@corp.com')}"}
    app.dependency_overrides[get_redis] = lambda: _BrokenRedis()
    assert client.get(f"{API}/users/me", headers=headers).status_code == 503
    assert client.post(f"{API}/auth/login", json={"email": "u@corp.com", "password": PASSWORD}).status_code == 503


def test_deactivated_user_cannot_login_and_old_token_dies(client, make_user, session_factory):
    uid = make_user("u@corp.com")
    headers = {"Authorization": f"Bearer {login(client, 'u@corp.com')}"}
    with session_factory() as db:
        db.get(User, uid).is_active = False
        db.commit()
    assert client.get(f"{API}/users/me", headers=headers).status_code == 401
    r = client.post(f"{API}/auth/login", json={"email": "u@corp.com", "password": PASSWORD})
    assert r.status_code == 401


def test_login_is_rate_limited_after_repeated_failures(client, make_user):
    make_user("u@corp.com")
    for _ in range(settings.login_max_attempts):
        r = client.post(f"{API}/auth/login", json={"email": "u@corp.com", "password": "wrong-wrong-wrong"})
        assert r.status_code == 401
    r = client.post(f"{API}/auth/login", json={"email": "u@corp.com", "password": PASSWORD})
    assert r.status_code == 429


def test_health_is_public_and_plain(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}