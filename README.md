# Customer Records API

A backend service for managing sensitive customer records. Built with FastAPI and PostgreSQL.

## Features
- Login and logout with JWT (RS256), passwords hashed with Argon2id
- Roles: USER, MANAGER, ADMIN, enforced on the server
- Customer CRUD, where users can only change their own records
- Responses with customer data are encrypted (AES-256-GCM + RSA-OAEP), so only the client with the matching private key can read them
- Admin endpoints to manage users and roles

## Tech stack
Python 3.12, FastAPI, SQLAlchemy, Alembic, PostgreSQL, Redis, pytest, uv

## Setup 
1. Install dependencies and create the signing keys:
```powershell
uv sync
uv run python -m scripts.generate_jwt_keys
```
2. Start PostgreSQL and Redis.
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

## Run the tests
```powershell
uv run pytest -v
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
| Encrypted responses | API3 Broken Object Property Level Authorization | AES-GCM + RSA-OAEP per response |
| CRUD | API3, API4 | strict input schemas, pagination limits |
| Ownership checks | API1 Broken Object Level Authorization | owner checked on every read, update, delete |
| Admin user management | API5, API6 | admin-only routes, self-lockout guards |

## Project structure
```
backend/api/   application code (routers, services, repositories, models, schemas, core)
alembic/       database migrations
client/        demo client and decryption helper
scripts/       create_admin, generate_jwt_keys
tests/         automated tests (43)
```

