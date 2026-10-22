import hashlib

from backend.api.core.config import settings


class LoginRateLimiter:
#Blocks an (IP + email) pair after too many failed logins.


    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window = window_seconds

    @staticmethod
    def _key(identity: str) -> str:
        return "login_fail:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def is_blocked(self, r, identity: str) -> bool:
        return int(r.get(self._key(identity)) or 0) >= self.max_attempts

    def record_failure(self, r, identity: str) -> None:
        key = self._key(identity)
        count = r.incr(key)
        if count == 1:  
            r.expire(key, self.window)

    def reset(self, r, identity: str) -> None:
        r.delete(self._key(identity))


login_limiter = LoginRateLimiter(settings.login_max_attempts, settings.login_window_seconds)