from functools import lru_cache

import redis

from backend.api.core.config import settings


@lru_cache(maxsize=1)
def _client() -> redis.Redis:
    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


def get_redis() -> redis.Redis:
    return _client()