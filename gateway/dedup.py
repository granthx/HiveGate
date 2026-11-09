"""In-flight singleflight coalescing and short-lived read caching."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from typing import Any, Awaitable, Callable


def call_key(tool: str, payload: dict[str, Any]) -> str:
    """Return a stable key for normalized tool input."""

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{tool}:{encoded}".encode()).hexdigest()


class Singleflight:
    """Merge identical reads while allowing write idempotency to be explicit."""

    def __init__(self, cache_ttl_s: float = 1.0) -> None:
        self.cache_ttl_s = cache_ttl_s
        self._inflight: dict[str, asyncio.Future[Any]] = {}
        self._cache: dict[str, tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def run(
        self,
        key: str,
        operation: Callable[[], Awaitable[Any]],
        *,
        cache_read: bool,
    ) -> tuple[Any, bool]:
        """Run once and return ``(result, shared_or_cached)``."""

        now = time.monotonic()
        async with self._lock:
            cached = self._cache.get(key)
            if cache_read and cached and cached[0] > now:
                return cached[1], True
            future = self._inflight.get(key)
            owner = future is None
            if owner:
                future = asyncio.get_running_loop().create_future()
                self._inflight[key] = future
        if not owner:
            return await future, True
        try:
            result = await operation()
            if cache_read:
                self._cache[key] = (time.monotonic() + self.cache_ttl_s, result)
            future.set_result(result)
            return result, False
        except Exception as exc:
            future.set_exception(exc)
            future.exception()
            raise
        finally:
            async with self._lock:
                self._inflight.pop(key, None)
