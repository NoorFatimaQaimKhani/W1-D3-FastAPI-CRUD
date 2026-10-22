import base64

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from client.crypto import decrypt_envelope, generate_keypair
from tests.conftest import create_customer

API = "/api/v1"


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
    put = lambda pem: client.put( 
        f"{API}/users/me/public-key", headers=alice.headers, json={"public_key_pem": pem}
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
    assert client.put(
        f"{API}/users/me/public-key", headers=alice.headers, json={"public_key_pem": new_public}
    ).status_code == 200
    envelope = client.get(f"{API}/customers", headers=alice.headers).json()
    assert decrypt_envelope(envelope, new_private)["items"]
    with pytest.raises(ValueError):
        decrypt_envelope(envelope, alice.private_pem)


def test_non_business_responses_stay_plain_json(client, actors):
    assert client.get("/health").json() == {"status": "ok"}
    err = client.get(f"{API}/customers/9999", headers=actors["alice"].headers)
    assert err.status_code == 404 and err.json() == {"detail": "Customer not found"}
    me = client.get(f"{API}/users/me", headers=actors["alice"].headers).json()
    assert me["email"] == "alice@corp.com"


def test_responses_are_not_cacheable(client, actors):
    r = client.get(f"{API}/customers", headers=actors["alice"].headers)
    assert r.headers["cache-control"] == "no-store"
