"""In-memory leased locks with monotonically increasing fencing tokens backed by store."""

from __future__ import annotations

from typing import Any

from .store import BaseStore, InMemoryStore, Lease


class LockManager:
    """Provides expiring locks and fencing tokens backed by BaseStore."""

    def __init__(self, store: BaseStore | None = None) -> None:
        self.store = store or InMemoryStore()

    async def acquire(self, resource: str, goal_id: str, agent_id: str, ttl_ms: int) -> Lease | None:
        return await self.store.acquire_lock(resource, goal_id, agent_id, ttl_ms)

    async def release(self, resource: str, token: int) -> bool:
        return await self.store.release_lock(resource, token)

    async def valid(self, resource: str, token: int) -> bool:
        return await self.store.is_lock_valid(resource, token)

    async def reset(self) -> None:
        await self.store.reset()
