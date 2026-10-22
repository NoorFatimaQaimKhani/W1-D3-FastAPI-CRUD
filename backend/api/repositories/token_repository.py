#Logout deny-list, stored in Redis.

import time


def key_for(jti: str) -> str:
    return f"revoked:{jti}"


def is_revoked(r, jti: str) -> bool:
    return bool(r.exists(key_for(jti)))


def revoke(r, jti: str, exp_timestamp: int) -> None:
    ttl = int(exp_timestamp - time.time())
    if ttl > 0:  
        r.set(key_for(jti), "1", ex=ttl)