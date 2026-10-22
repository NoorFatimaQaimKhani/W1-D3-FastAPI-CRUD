
import argparse
import json
import uuid

import httpx

from client.crypto import decrypt_envelope, generate_keypair


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    base = parser.parse_args().base_url.rstrip("/") + "/api/v1"

    email = f"demo-{uuid.uuid4().hex[:8]}@corp.com"
    password = uuid.uuid4().hex + "Aa1!"

    with httpx.Client(timeout=15) as http:
        r = http.post(f"{base}/auth/register", json={"email": email, "password": password})
        print("register        ->", r.status_code, r.json())

        r = http.post(f"{base}/auth/login", json={"email": email, "password": password})
        token = r.json()["access_token"]
        auth = {"Authorization": f"Bearer {token}"}
        print("login           ->", r.status_code, "(token received)")

        r = http.post(f"{base}/customers", headers=auth, json={"full_name": "No Key Yet"})
        print("customer w/o key->", r.status_code, r.json())

        private_pem, public_pem = generate_keypair()
        r = http.put(
            f"{base}/users/me/public-key",
            headers=auth,
            json={"public_key_pem": public_pem, "current_password": password},
        )
        print("register key    ->", r.status_code, r.json()["public_key_fingerprint"][:16], "...")

        r = http.post(
            f"{base}/customers",
            headers=auth,
            json={"full_name": "Ada Lovelace", "email": "ada@corp.com", "notes": "VIP"},
        )
        print("\nRAW create response (what a network observer / Swagger sees):")
        print(json.dumps(r.json(), indent=2)[:400], "...")
        created = decrypt_envelope(r.json(), private_pem)
        print("\nDECRYPTED create response:", created)

        r = http.get(f"{base}/customers", headers=auth)
        print("DECRYPTED list:", decrypt_envelope(r.json(), private_pem))

        r = http.post(f"{base}/auth/logout", headers=auth)
        print("\nlogout          ->", r.status_code)
        r = http.get(f"{base}/users/me", headers=auth)
        print("reuse old token ->", r.status_code, r.json())


if __name__ == "__main__":
    main()
