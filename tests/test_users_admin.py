from tests.conftest import create_customer

API = "/api/v1"


def test_non_admins_cannot_use_user_management(client, actors):
    bob_id = actors["bob"].id
    for who in ("alice", "mia"): 
        h = actors[who].headers
        assert client.get(f"{API}/users", headers=h).status_code == 403
        assert client.get(f"{API}/users/{bob_id}", headers=h).status_code == 403
        assert client.patch(f"{API}/users/{bob_id}", headers=h, json={"role": "ADMIN"}).status_code == 403
        assert client.delete(f"{API}/users/{bob_id}", headers=h).status_code == 403


def test_user_management_requires_authentication(client):
    assert client.get(f"{API}/users").status_code == 401
    assert client.patch(f"{API}/users/1", json={"role": "ADMIN"}).status_code == 401


def test_admin_can_list_and_get_users_without_secrets(client, actors):
    ada = actors["ada"]
    users = client.get(f"{API}/users", headers=ada.headers).json()
    assert {u["email"] for u in users} == {f"{n}@corp.com" for n in ("alice", "bob", "mia", "ada")}
    assert all("hashed_password" not in u and "public_key_pem" not in u for u in users)
    one = client.get(f"{API}/users/{actors['bob'].id}", headers=ada.headers)
    assert one.status_code == 200 and one.json()["email"] == "bob@corp.com"
    assert client.get(f"{API}/users/9999", headers=ada.headers).status_code == 404


def test_role_change_takes_effect_immediately(client, actors):
    ada, alice, bob = actors["ada"], actors["alice"], actors["bob"]
    create_customer(client, bob, "Bob's")

    before = alice.decrypt(client.get(f"{API}/customers", headers=alice.headers))
    assert before["items"] == []  

    r = client.patch(f"{API}/users/{alice.id}", headers=ada.headers, json={"role": "MANAGER"})
    assert r.status_code == 200 and r.json()["role"] == "MANAGER"

    after = alice.decrypt(client.get(f"{API}/customers", headers=alice.headers))  # SAME token
    assert [c["full_name"] for c in after["items"]] == ["Bob's"]


def test_admin_can_deactivate_a_user(client, actors):
    ada, bob = actors["ada"], actors["bob"]
    r = client.patch(f"{API}/users/{bob.id}", headers=ada.headers, json={"is_active": False})
    assert r.status_code == 200 and r.json()["is_active"] is False
    assert client.get(f"{API}/users/me", headers=bob.headers).status_code == 401


def test_invalid_updates_are_rejected(client, actors):
    ada, bob = actors["ada"], actors["bob"]
    assert client.patch(f"{API}/users/{bob.id}", headers=ada.headers, json={"role": "ROOT"}).status_code == 422
    assert client.patch(f"{API}/users/{bob.id}", headers=ada.headers, json={}).status_code == 422
    assert client.patch(f"{API}/users/{bob.id}", headers=ada.headers, json={"email": "x@y.com"}).status_code == 422


def test_admin_cannot_lock_themselves_out(client, actors):
    ada = actors["ada"]
    assert client.patch(f"{API}/users/{ada.id}", headers=ada.headers, json={"role": "USER"}).status_code == 400
    assert client.patch(f"{API}/users/{ada.id}", headers=ada.headers, json={"is_active": False}).status_code == 400
    assert client.delete(f"{API}/users/{ada.id}", headers=ada.headers).status_code == 400
    assert client.get(f"{API}/users/me", headers=ada.headers).json()["role"] == "ADMIN"


def test_delete_user_blocked_while_they_own_records(client, actors):
    ada, alice, bob = actors["ada"], actors["alice"], actors["bob"]
    cid = create_customer(client, alice)["id"]
    assert client.delete(f"{API}/users/{alice.id}", headers=ada.headers).status_code == 409

    assert client.delete(f"{API}/customers/{cid}", headers=ada.headers).status_code == 204
    assert client.delete(f"{API}/users/{alice.id}", headers=ada.headers).status_code == 204
    assert client.get(f"{API}/users/{alice.id}", headers=ada.headers).status_code == 404
    assert client.delete(f"{API}/users/{bob.id}", headers=ada.headers).status_code == 204
