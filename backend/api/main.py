from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError

from backend.api.api_v1.router import api_router
from backend.api.core.config import settings

is_production = settings.environment.lower() == "production"

app = FastAPI(
    title="Customer Records API",
    version="1.0.0",
    docs_url=None if is_production else "/docs",
    redoc_url=None,
    openapi_url=None if is_production else "/openapi.json",
)


@app.exception_handler(RedisError)
async def redis_unavailable(request: Request, exc: RedisError):
    return JSONResponse(status_code=503, content={"detail": "Service temporarily unavailable"})


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}  


app.include_router(api_router, prefix="/api/v1")