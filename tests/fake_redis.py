"""Tiny in-memory stand-in for redis.Redis (decode_responses=True), covering only the
commands the app uses. Lets the test-suite run without a Redis server."""

import time


class FakeRedis:
    def __init__(self):
        self._data: dict[str, tuple[str, float | None]] = {}

    def _live(self, name: str):
        item = self._data.get(name)
        if item is None:
            return None
        value, expires_at = item
        if expires_at is not None and expires_at <= time.monotonic():
            del self._data[name]
            return None
        return item

    def set(self, name, value, ex=None):
        expires_at = time.monotonic() + ex if ex else None
        self._data[name] = (str(value), expires_at)
        return True

    def get(self, name):
        item = self._live(name)
        return item[0] if item else None

    def exists(self, name):
        return 1 if self._live(name) else 0

    def incr(self, name):
        item = self._live(name)
        count = int(item[0]) + 1 if item else 1
        expires_at = item[1] if item else None
        self._data[name] = (str(count), expires_at)
        return count

    def expire(self, name, seconds):
        item = self._live(name)
        if not item:
            return False
        self._data[name] = (item[0], time.monotonic() + seconds)
        return True

    def delete(self, name):
        return 1 if self._data.pop(name, None) is not None else 0

    def ttl(self, name):
        item = self._live(name)
        if not item:
            return -2
        if item[1] is None:
            return -1
        return int(item[1] - time.monotonic())