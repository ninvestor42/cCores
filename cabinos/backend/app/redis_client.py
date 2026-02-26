import time
from typing import Dict, Tuple

import redis

from app.config import settings


class InMemoryRedis:
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[str, float | None]] = {}

    def _alive(self, key: str) -> bool:
        if key not in self._data:
            return False
        _, expires_at = self._data[key]
        if expires_at is not None and time.time() > expires_at:
            self._data.pop(key, None)
            return False
        return True

    def incr(self, key: str) -> int:
        if not self._alive(key):
            self._data[key] = ('0', None)
        val = int(self._data[key][0]) + 1
        self._data[key] = (str(val), self._data[key][1])
        return val

    def expire(self, key: str, seconds: int) -> bool:
        if not self._alive(key):
            return False
        self._data[key] = (self._data[key][0], time.time() + seconds)
        return True

    def set(self, key: str, value: str, nx: bool = False, ex: int | None = None):
        exists = self._alive(key)
        if nx and exists:
            return False
        self._data[key] = (value, time.time() + ex if ex else None)
        return True


try:
    r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    r.ping()
except Exception:
    r = InMemoryRedis()
