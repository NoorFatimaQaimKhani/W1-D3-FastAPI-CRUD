# This file creates two throw-away USER accounts (alice and bob) for roles with different permissions.

import argparse
import sys
import uuid

import httpx

from client.crypto import decrypt_envelope, generate_keypair


def make_user(http: httpx.Client, base: str, label: str):
    email = f"{label}-{uuid.uuid4().hex[:8]}@corp.com"
    password = uuid.uuid4().hex + "Aa1!"
    http.post(f"{base}/auth/register", json={"email": email, "password": password})
    token = http.post(f"{base}/auth/login", json={"email": email, "password": password}).json()[
        "access_token"
    ]
    headers = {"Authorization": f"Bearer {token}"}
    private_pem, public_pem = generate_keypair()
    http.put(f"{base}/users/me/public-key", headers=headers, json={"public_key_pem": public_pem})
    return headers, private_pem


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    base = parser.parse_args().base_url.rstrip("/") + "/api/v1"

    failures = []

    def check(label: str, got: int, expected: int) -> None:
        ok = got == expected
        print(f"{'PASS' if ok else 'FAIL'}  {label:<48} -> {got} (expected {expected})")
        if not ok:
            failures.append(label)

    with httpx.Client(timeout=15) as http:
        alice, alice_key = make_user(http, base, "alice")
        bob, _bob_key = make_user(http, base, "bob")

        r = http.post(f"{base}/customers", headers=alice, json={"full_name": "Alice's Customer"})
        check("Alice creates a customer", r.status_code, 201)
        cid = decrypt_envelope(r.json(), alice_key)["id"]
        print(f"      (record id {cid} belongs to Alice)\n")

        check("Bob READS Alice's record", http.get(f"{base}/customers/{cid}", headers=bob).status_code, 404)
        check(
            "Bob EDITS Alice's record",
            http.patch(f"{base}/customers/{cid}", headers=bob, json={"notes": "hacked"}).status_code,
            404,
        )
        check("Bob DELETES Alice's record", http.delete(f"{base}/customers/{cid}", headers=bob).status_code, 404)

        r = http.get(f"{base}/customers", headers=bob)
        bob_list = decrypt_envelope(r.json(), _bob_key)["items"]
        check("Bob's own list does not contain it", len([c for c in bob_list if c["id"] == cid]), 0)

        r = http.get(f"{base}/customers/{cid}", headers=alice)
        check("Alice can still READ her record", r.status_code, 200)
        r = http.patch(f"{base}/customers/{cid}", headers=alice, json={"notes": "mine"})
        check("Alice can EDIT her record", r.status_code, 200)
        check("Alice can DELETE her record", http.delete(f"{base}/customers/{cid}", headers=alice).status_code, 204)

    print("\nAll ownership checks passed." if not failures else f"\n{len(failures)} check(s) FAILED.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()