import base64

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from client.crypto import (
    decrypt_envelope,
    generate_keypair,
    sign_key_rotation_challenge,
)
from tests.conftest import create_customer

API = "/api/v1"
PASSWORD = "correct-horse-battery"


def test_response_is_an_envelope_with_no_plaintext(client, actors):
    alice = actors["alice"]
    r = client.post(
        f"{API}/customers", headers=alice.headers,
        json={"full_name": "Zebulon Quux", "email": "zq@corp.com", "notes": "top secret"},
    )
    assert r.status_code == 201
    assert set(r.json()) == {"alg", "key_fingerprint", "encrypted_key", "nonce", "ciphertext"}
    for secret in ("Zebulon", "zq@corp.com", "top secret", "owner_id"):
        assert secret not in r.text
    assert r.json()["alg"] == "RSA-OAEP-SHA256+A256GCM"


def test_only_the_registered_private_key_can_decrypt(client, actors):
    alice, bob = actors["alice"], actors["bob"]
    create_customer(client, alice, "Private")
    envelope = client.get(f"{API}/customers", headers=alice.headers).json()

    assert decrypt_envelope(envelope, alice.private_pem)["items"][0]["full_name"] == "Private"
    with pytest.raises(ValueError):  
        decrypt_envelope(envelope, bob.private_pem)


def test_each_user_gets_data_encrypted_to_their_own_key(client, actors):
    alice, ada = actors["alice"], actors["ada"]
    cid = create_customer(client, alice, "Shared")["id"]
    r = client.get(f"{API}/customers/{cid}", headers=ada.headers)
    assert ada.decrypt(r)["full_name"] == "Shared"
    with pytest.raises(ValueError):
        decrypt_envelope(r.json(), alice.private_pem)


def test_tampering_is_detected(client, actors):
    alice = actors["alice"]
    create_customer(client, alice)
    envelope = client.get(f"{API}/customers", headers=alice.headers).json()

    raw = bytearray(base64.b64decode(envelope["ciphertext"]))
    raw[0] ^= 0x01
    tampered = {**envelope, "ciphertext": base64.b64encode(bytes(raw)).decode()}
    with pytest.raises(InvalidTag):
        decrypt_envelope(tampered, alice.private_pem)


def test_fresh_key_and_nonce_for_every_response(client, actors):
    alice = actors["alice"]
    create_customer(client, alice)
    a = client.get(f"{API}/customers", headers=alice.headers).json()
    b = client.get(f"{API}/customers", headers=alice.headers).json()
    assert a["nonce"] != b["nonce"]
    assert a["encrypted_key"] != b["encrypted_key"]
    assert a["ciphertext"] != b["ciphertext"]


def test_fingerprint_matches_registered_key(client, actors):
    alice = actors["alice"]
    me = client.get(f"{API}/users/me", headers=alice.headers).json()
    create_customer(client, alice)
    envelope = client.get(f"{API}/customers", headers=alice.headers).json()
    assert envelope["key_fingerprint"] == me["public_key_fingerprint"]
    assert "public_key_pem" not in me


def _pem_pub(key) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def test_bad_public_keys_are_rejected(client, actors):
    alice = actors["alice"]

    def put(pem):
        challenge = client.post(
            f"{API}/users/me/public-key/challenge", headers=alice.headers
        ).json()
        return client.put(
            f"{API}/users/me/public-key",
            headers=alice.headers,
            json={
                "public_key_pem": pem,
                "current_password": PASSWORD,
                "rotation_challenge_id": challenge["challenge_id"],
                "rotation_signature": sign_key_rotation_challenge(
                    alice.private_pem, challenge["challenge"]
                ),
            },
        )

    weak = rsa.generate_private_key(65537, 1024)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = generate_keypair()[0].decode()

    assert put("x" * 100).status_code == 422  
    assert put(_pem_pub(weak)).status_code == 422 
    assert put(_pem_pub(ec_key)).status_code == 422  
    assert put(private_pem).status_code == 422  


def test_key_rotation_applies_to_next_response(client, actors):
    alice = actors["alice"]
    create_customer(client, alice)
    new_private, new_public = generate_keypair()
    challenge_response = client.post(
        f"{API}/users/me/public-key/challenge", headers=alice.headers
    )
    assert challenge_response.status_code == 200
    challenge = challenge_response.json()
    assert client.put(
        f"{API}/users/me/public-key",
        headers=alice.headers,
        json={
            "public_key_pem": new_public,
            "current_password": PASSWORD,
            "rotation_challenge_id": challenge["challenge_id"],
            "rotation_signature": sign_key_rotation_challenge(
                alice.private_pem, challenge["challenge"]
            ),
        },
    ).status_code == 200
    envelope = client.get(f"{API}/customers", headers=alice.headers).json()
    assert decrypt_envelope(envelope, new_private)["items"]
    with pytest.raises(ValueError):
        decrypt_envelope(envelope, alice.private_pem)


def test_key_rotation_requires_password_and_proof_of_current_key(client, actors):
    alice = actors["alice"]
    _, new_public = generate_keypair()
    endpoint = f"{API}/users/me/public-key"

    assert client.put(
        endpoint,
        headers=alice.headers,
        json={"public_key_pem": new_public, "current_password": "wrong-password"},
    ).status_code == 403

    assert client.put(
        endpoint,
        headers=alice.headers,
        json={"public_key_pem": new_public, "current_password": PASSWORD},
    ).status_code == 403

    challenge = client.post(
        f"{API}/users/me/public-key/challenge", headers=alice.headers
    ).json()
    wrong_signature = sign_key_rotation_challenge(
        actors["bob"].private_pem, challenge["challenge"]
    )
    assert client.put(
        endpoint,
        headers=alice.headers,
        json={
            "public_key_pem": new_public,
            "current_password": PASSWORD,
            "rotation_challenge_id": challenge["challenge_id"],
            "rotation_signature": wrong_signature,
        },
    ).status_code == 403

    # Challenges are single-use, even after an invalid signature attempt.
    assert client.put(
        endpoint,
        headers=alice.headers,
        json={
            "public_key_pem": new_public,
            "current_password": PASSWORD,
            "rotation_challenge_id": challenge["challenge_id"],
            "rotation_signature": sign_key_rotation_challenge(
                alice.private_pem, challenge["challenge"]
            ),
        },
    ).status_code == 403


def test_initial_key_registration_requires_current_password(client, make_user):
    make_user("nokey@corp.com")
    token = client.post(
        f"{API}/auth/login",
        json={"email": "nokey@corp.com", "password": PASSWORD},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    _, public_key = generate_keypair()
    response = client.put(
        f"{API}/users/me/public-key",
        headers=headers,
        json={"public_key_pem": public_key},
    )
    assert response.status_code == 422


def test_non_business_responses_stay_plain_json(client, actors):
    assert client.get("/health").json() == {"status": "ok"}
    err = client.get(f"{API}/customers/9999", headers=actors["alice"].headers)
    assert err.status_code == 404 and err.json() == {"detail": "Customer not found"}
    me = client.get(f"{API}/users/me", headers=actors["alice"].headers).json()
    assert me["email"] == "alice@corp.com"


def test_responses_are_not_cacheable(client, actors):
    r = client.get(f"{API}/customers", headers=actors["alice"].headers)
    assert r.headers["cache-control"] == "no-store"
