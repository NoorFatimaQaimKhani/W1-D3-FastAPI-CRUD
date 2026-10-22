from fastapi import APIRouter

from backend.api.api_v1.endpoints import auth, customers, users

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(customers.router)
