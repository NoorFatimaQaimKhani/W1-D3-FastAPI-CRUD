# Customer Records API

A backend service for managing sensitive customer records. Built with FastAPI and PostgreSQL.

## Features
- Login and logout with JWT (RS256), passwords hashed with Argon2id
- Roles: USER, MANAGER, ADMIN, enforced on the server
- Customer CRUD, where users can only change their own records
- Responses with customer data are encrypted (AES-256-GCM + RSA-OAEP), so only the client with the matching private key can read them
- Public-key registration requires the current password; key rotation additionally requires a one-time challenge signed by the existing private key
- Admin endpoints to manage users and roles

## Tech stack
Python 3.12, FastAPI, SQLAlchemy, Alembic, PostgreSQL, Redis, pytest, uv

## Setup 
1. Install dependencies and create the signing keys:
```powershell
uv sync
uv run python -m scripts.generate_jwt_keys
```
2. Start PostgreSQL and Redis. Keep both private to the application network and use TLS/authentication in deployed environments.
3. Create a `.env` file in the project root:
```
DATABASE_URL=postgresql+psycopg2://USERNAME:PASSWORD@localhost:5432/DATABASE_NAME
REDIS_URL=redis://:PASSWORD@localhost:6379/0
JWT_PRIVATE_KEY_PATH=keys/jwt_private.pem
JWT_PUBLIC_KEY_PATH=keys/jwt_public.pem
```
4. Create the tables, the first admin, and start the server:
```powershell
uv run alembic upgrade head
uv run python -m scripts.create_admin
uv run uvicorn backend.api.main:app --reload
```
Swagger UI: http://127.0.0.1:8000/docs

### Registering or rotating a response-encryption key

Initial registration at `PUT /api/v1/users/me/public-key` requires `public_key_pem` and `current_password`. For key rotation, first request `POST /api/v1/users/me/public-key/challenge`, sign its returned `challenge` string with the currently registered RSA private key using RSA-PSS/SHA-256, then send the challenge ID and Base64 signature with the new public key and current password. Challenges expire after five minutes and are single-use. Redis 6.2 or newer is required for atomic single-use challenge consumption. The private key must remain on the client and must never be uploaded.

## Run the tests

The test suite runs against PostgreSQL, Redis, and the Alembic migration. Start the disposable local test services and configure their connection URLs before running it:

```powershell
docker compose -f compose.integration.yml up -d --wait
$env:DATABASE_URL = "postgresql+psycopg2://customer_records:customer_records_test@localhost:5433/customer_records_test"
$env:REDIS_URL = "redis://localhost:6380/15"
uv run pytest -v
```

Tests refuse non-local PostgreSQL databases or databases not named with the `_test` suffix, require Redis on a nonzero database index, apply `alembic upgrade head`, and truncate the test tables between cases. Do not point tests at production or shared services. The Compose services bind only to localhost and are intended for local testing, not deployment. Stop the services and clear the test URLs when finished:

```powershell
docker compose -f compose.integration.yml down
Remove-Item Env:DATABASE_URL, Env:REDIS_URL
```


## Roles and permissions
| Action | USER | MANAGER | ADMIN |
|---|---|---|---|
| Create customer | yes | yes | yes |
| View customers | own | all | all |
| Update / delete customer | own | own | all |
| Manage users and roles | no | no | yes |

## Security (OWASP API Security Top 10, 2023)
| Requirement | Risk | How |
|---|---|---|
| Login / logout with JWT | API2 Broken Authentication | RS256 tokens, Argon2id, logout revocation in Redis, login rate limit |
| Roles | API5 Broken Function Level Authorization | server-side role checks |
| Encrypted responses | API3 Broken Object Property Level Authorization | AES-GCM + RSA-OAEP per response; key registration requires password confirmation and rotation proves possession of the previous key |
| CRUD | API3, API4 | strict input schemas, pagination limits |
| Ownership checks | API1 Broken Object Level Authorization | owner checked on every read, update, delete |
| Admin user management | API5, API6 | admin-only routes, self-lockout guards |

## Project structure
```
backend/api/   application code (routers, services, repositories, models, schemas, core)
alembic/       database migrations
client/        demo client and decryption helper
scripts/       create_admin, generate_jwt_keys
tests/         unit and opt-in PostgreSQL/Redis integration tests
```
