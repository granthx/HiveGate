"""Bounded adaptive concurrency admission for upstream calls."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")


class AdmissionRejected(Exception):
    """Raised when the bounded waiting queue is full."""


class AdaptiveLimiter:
    """A small AIMD-style limiter with a bounded async wait queue."""

    def __init__(self, initial: int = 4, maximum: int = 32, queue_limit: int = 100) -> None:
        self.initial = initial
        self.limit = initial
        self.maximum = max(initial, maximum)
        self.queue_limit = queue_limit
        self.active = 0
        self.waiting = 0
        self._condition = asyncio.Condition()

    async def run(self, operation: Callable[[], Awaitable[T]]) -> T:
        async with self._condition:
            if self.active >= self.limit:
                if self.waiting >= self.queue_limit:
                    raise AdmissionRejected
                self.waiting += 1
                try:
                    await self._condition.wait_for(lambda: self.active < self.limit)
                finally:
                    self.waiting -= 1
            self.active += 1
        try:
            result = await operation()
        except Exception:
            await self.failure()
            raise
        else:
            await self.success()
            return result
        finally:
            async with self._condition:
                self.active -= 1
                self._condition.notify_all()

    async def success(self) -> None:
        async with self._condition:
            self.limit = min(self.maximum, self.limit + 1)

    async def failure(self) -> None:
        async with self._condition:
            self.limit = max(1, self.limit // 2)

    def reset(self) -> None:
        self.limit = self.initial
        self.active = 0
        self.waiting = 0

    def snapshot(self) -> dict[str, int]:
        return {"limit": self.limit, "active": self.active, "waiting": self.waiting, "maximum": self.maximum}
