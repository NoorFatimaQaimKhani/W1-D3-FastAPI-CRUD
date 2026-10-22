from tests.conftest import create_customer, login

API = "/api/v1"


# ---------- CRUD ----------
def test_full_crud_cycle_for_owner(client, actors):
    alice = actors["alice"]
    created = create_customer(client, alice, "Ada Lovelace", email="ada@corp.com", phone="+44 20 7946 0958")
    assert created["owner_id"] == alice.id and created["full_name"] == "Ada Lovelace"
    cid = created["id"]

    got = alice.decrypt(client.get(f"{API}/customers/{cid}", headers=alice.headers))
    assert got["email"] == "ada@corp.com"

    patched = alice.decrypt(
        client.patch(f"{API}/customers/{cid}", headers=alice.headers, json={"notes": "VIP"})
    )
    assert patched["notes"] == "VIP" and patched["full_name"] == "Ada Lovelace"  # untouched field kept

    assert client.delete(f"{API}/customers/{cid}", headers=alice.headers).status_code == 204
    assert client.get(f"{API}/customers/{cid}", headers=alice.headers).status_code == 404


def test_input_validation(client, actors):
    alice = actors["alice"]
    post = lambda body: client.post(f"{API}/customers", headers=alice.headers, json=body)  
    assert post({}).status_code == 422  
    assert post({"full_name": "x", "email": "bad"}).status_code == 422
    assert post({"full_name": "x", "phone": "abc"}).status_code == 422
    assert post({"full_name": "x" * 500}).status_code == 422
    assert post({"full_name": "x", "owner_id": actors["bob"].id}).status_code == 422  
    r = client.patch(f"{API}/customers/1", headers=alice.headers, json={"full_name": None})
    assert r.status_code == 422


def test_pagination_limits(client, actors):
    alice = actors["alice"]
    for i in range(3):
        create_customer(client, alice, f"C{i}")
    page = alice.decrypt(client.get(f"{API}/customers?limit=2&offset=0", headers=alice.headers))
    assert len(page["items"]) == 2 and page["limit"] == 2
    page2 = alice.decrypt(client.get(f"{API}/customers?limit=2&offset=2", headers=alice.headers))
    assert len(page2["items"]) == 1
    assert client.get(f"{API}/customers?limit=1000", headers=alice.headers).status_code == 422
    assert client.get(f"{API}/customers?offset=-1", headers=alice.headers).status_code == 422


def test_customer_endpoints_require_authentication(client):
    assert client.get(f"{API}/customers").status_code == 401
    assert client.post(f"{API}/customers", json={"full_name": "x"}).status_code == 401
    assert client.get(f"{API}/customers/1").status_code == 401
    assert client.patch(f"{API}/customers/1", json={"notes": "x"}).status_code == 401
    assert client.delete(f"{API}/customers/1").status_code == 401


def test_customer_data_requires_a_registered_public_key(client, make_user):
    make_user("nokey@corp.com")
    headers = {"Authorization": f"Bearer {login(client, 'nokey@corp.com')}"}
    r = client.post(f"{API}/customers", headers=headers, json={"full_name": "x"})
    assert r.status_code == 428
    assert client.get(f"{API}/customers", headers=headers).status_code == 428


def test_user_sees_only_own_records_manager_and_admin_see_all(client, actors):
    create_customer(client, actors["alice"], "Alice's")
    create_customer(client, actors["bob"], "Bob's")

    def names(actor):
        data = actor.decrypt(client.get(f"{API}/customers", headers=actor.headers))
        return sorted(c["full_name"] for c in data["items"])

    assert names(actors["alice"]) == ["Alice's"]
    assert names(actors["bob"]) == ["Bob's"]
    assert names(actors["mia"]) == ["Alice's", "Bob's"]
    assert names(actors["ada"]) == ["Alice's", "Bob's"]


def test_user_cannot_read_someone_elses_record(client, actors):
    cid = create_customer(client, actors["alice"])["id"]
    r = client.get(f"{API}/customers/{cid}", headers=actors["bob"].headers)
    assert r.status_code == 404  
    assert actors["mia"].decrypt(client.get(f"{API}/customers/{cid}", headers=actors["mia"].headers))
    assert actors["ada"].decrypt(client.get(f"{API}/customers/{cid}", headers=actors["ada"].headers))


def test_user_cannot_update_or_delete_others_records(client, actors):
    alice, bob = actors["alice"], actors["bob"]
    cid = create_customer(client, alice, "Original")["id"]

    assert client.patch(f"{API}/customers/{cid}", headers=bob.headers, json={"full_name": "Hacked"}).status_code == 404
    assert client.delete(f"{API}/customers/{cid}", headers=bob.headers).status_code == 404
    still = alice.decrypt(client.get(f"{API}/customers/{cid}", headers=alice.headers))
    assert still["full_name"] == "Original"


def test_manager_can_view_all_but_modify_only_own(client, actors):
    alice, mia = actors["alice"], actors["mia"]
    alices = create_customer(client, alice, "Alice's")["id"]
    mias = create_customer(client, mia, "Mia's")["id"]

    # sees Alice's record, but modifying it is forbidden (403, not 404: she can see it)
    assert client.patch(f"{API}/customers/{alices}", headers=mia.headers, json={"notes": "x"}).status_code == 403
    assert client.delete(f"{API}/customers/{alices}", headers=mia.headers).status_code == 403
    assert alice.decrypt(client.get(f"{API}/customers/{alices}", headers=alice.headers))["notes"] is None

    # her own record: full control
    assert client.patch(f"{API}/customers/{mias}", headers=mia.headers, json={"notes": "mine"}).status_code == 200
    assert client.delete(f"{API}/customers/{mias}", headers=mia.headers).status_code == 204


def test_admin_can_update_and_delete_any_record(client, actors):
    alice, ada = actors["alice"], actors["ada"]
    cid = create_customer(client, alice, "Alice's")["id"]
    r = client.patch(f"{API}/customers/{cid}", headers=ada.headers, json={"notes": "by admin"})
    assert ada.decrypt(r)["notes"] == "by admin"
    assert client.delete(f"{API}/customers/{cid}", headers=ada.headers).status_code == 204
    assert client.get(f"{API}/customers/{cid}", headers=alice.headers).status_code == 404


def test_missing_record_is_404(client, actors):
    assert client.get(f"{API}/customers/9999", headers=actors["ada"].headers).status_code == 404
    assert client.delete(f"{API}/customers/9999", headers=actors["ada"].headers).status_code == 404
