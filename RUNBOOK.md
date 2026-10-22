# Customer Records API: Runbook

(Your existing `README.md` is untouched. This file is separate.)

## 1. Install the bundle (PowerShell, from the project root)

```powershell
cd "D:\Intraship case study\PRAC\customer-records"

# back up the file this bundle replaces (main.py was empty; connection.py is changed, see "What changed")
Copy-Item backend\api\db\connection.py backend\api\db\connection.py.bak

# adjust the path if the zip is not in Downloads
Expand-Archive -Path "$HOME\Downloads\customer-records-backend.zip" -DestinationPath . -Force

# 2 extra dependencies (email validation; test tooling)
uv add email-validator
uv add --dev pytest httpx

# generate a JWT signing secret and append it to .env (leading newline protects the last line of .env)
$key = uv run python -c "import secrets; print(secrets.token_urlsafe(48))"
Add-Content -Path .env -Value "`nSECRET_KEY=$key"

# never commit key files
Add-Content -Path .gitignore -Value "`n*.pem"
```

`src/`, `pyproject.toml` packaging, `test.py` and your `.env` DATABASE_URL are not modified.
Import/run strategy: **everything runs from the project root as `backend.api...`** (`uvicorn backend.api.main:app`, `python -m scripts.create_admin`, `pytest` via `pytest.ini`). `src/` is simply unused.

## 2. Run the tests (uses in-memory SQLite, never your PostgreSQL)

```powershell
uv run pytest -v
```

Expected: all tests pass (about 50). If something fails, paste the failure output.

## 3. Create the first admin, start the server

```powershell
uv run python -m scripts.create_admin     # hidden password prompt
uv run uvicorn backend.api.main:app --reload
```

Tables are created automatically on startup. Swagger UI: http://127.0.0.1:8000/docs

Swagger flow: `POST /api/v1/auth/login` -> copy `access_token` -> **Authorize** button -> paste token.
Customer endpoints return an *encrypted envelope* in Swagger (that is the point); to see decrypted data run the demo in a second terminal:

```powershell
uv run python -m client.demo
```

## 4. Endpoints

| Method | Path | Who | Notes |
|---|---|---|---|
| POST | /api/v1/auth/register | public | always creates role USER |
| POST | /api/v1/auth/login | public | JSON `{email, password}`; rate limited |
| POST | /api/v1/auth/logout | any user | revokes the token (jti deny-list) |
| GET | /api/v1/users/me | any user | |
| PUT | /api/v1/users/me/public-key | any user | register/rotate RSA-2048+ public key |
| GET/GET{id}/PATCH{id}/DELETE{id} | /api/v1/users | ADMIN | role / is_active changes, delete |
| POST/GET/GET{id}/PATCH{id}/DELETE{id} | /api/v1/customers | see matrix | success bodies are encrypted (DELETE = 204) |
| GET | /health | public | plain JSON |

Permissions: view = USER own / MANAGER all / ADMIN all; update+delete = USER own / MANAGER own / ADMIN all. Foreign records are 404 for a USER (existence hidden), 403 for a MANAGER trying to modify (they can see it).

## 5. Encryption design (decisions)

- Client generates an RSA-2048+ key pair and registers only the **public** key (`PUT /users/me/public-key`). Private key never leaves the client.
- Customer endpoints return 428 until a key is registered.
- Per response: fresh AES-256 key + 96-bit nonce -> AES-GCM; AES key wrapped with RSA-OAEP (SHA-256).
- Envelope: `alg, key_fingerprint, encrypted_key, nonce, ciphertext` (base64; `ciphertext` = data + 16-byte GCM tag).
- Plain (not encrypted): login/logout, health, key registration, user management, and all error bodies. These carry no customer data.
- Decrypt reference: `client/crypto.py`. Still use HTTPS in front of this.

## 6. OWASP API Top 10 (2023) mapping

| Risk | Where addressed |
|---|---|
| API1 BOLA | `customer_service._get_authorized` + `core/permissions.py`; tests in `test_customers.py` |
| API2 Broken authentication | Argon2, short-lived signed JWT (iss/aud/exp/jti validated, alg pinned), logout revocation, login rate limit, uniform login errors, timing equalisation |
| API3 Broken object property level auth | Pydantic `extra="forbid"` (no role/owner_id injection), explicit response schemas (no hashes/keys) |
| API4 Unrestricted resource consumption | pagination caps (limit <= 100), max field lengths, password max 128, login throttling |
| API5 Broken function level auth | `require_roles(Role.ADMIN)` on every user-management route, server-side |
| API6 Unrestricted access to sensitive business flows | self-registration cannot grant roles; admin self-lockout guard; delete blocked while user owns records |
| API7 SSRF | not applicable: the API never fetches user-supplied URLs |
| API8 Security misconfiguration | secrets only from env, `SQL echo` off by default, docs/OpenAPI hidden when `ENVIRONMENT=production`, `Cache-Control: no-store`, `nosniff` |
| API9 Improper inventory management | single versioned prefix `/api/v1`, documented endpoint table above |
| API10 Unsafe consumption of APIs | uploaded public keys strictly validated (RSA only, >= 2048 bits, never a private key) |

## 7. Production to-do (not done here, by design)

- HTTPS termination (reverse proxy), HSTS.
- Alembic migrations instead of `create_all`.
- Move the login limiter and token deny-list cache to Redis if you run several instances.
- Least-privilege DB role (no DDL rights for the app user); secret manager for `SECRET_KEY`/`DATABASE_URL`.
- Structured logging that never logs request/response bodies; audit log of admin actions.
- Registration returns 409 for existing emails (reveals that an email is registered); acceptable here, otherwise switch to email verification.
- CORS config if a browser front end is added.

## 8. Troubleshooting

- `ValidationError ... secret_key Field required`: `SECRET_KEY` missing from `.env` (step 1).
- `ImportError: email-validator is not installed`: run `uv add email-validator`.
- `ModuleNotFoundError: backend`: run commands from the project root, not from a sub-folder.
- DB connection errors: confirm the Docker container is running and `DATABASE_URL` in `.env` is right.
- 428 on customers: register a public key first (the demo does this automatically).
