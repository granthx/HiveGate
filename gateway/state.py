"""Goal-scoped versioned state with compare-and-set writes backed by store."""

from __future__ import annotations

from typing import Any

from .store import BaseStore, InMemoryStore, StateConflict, VersionedValue


class StateStore:
    """Process-local or distributed CAS state store backed by BaseStore."""

    def __init__(self, store: BaseStore | None = None) -> None:
        self.store = store or InMemoryStore()

    async def get(self, goal_id: str, key: str) -> VersionedValue | None:
        return await self.store.get_state(goal_id, key)

    async def put(self, goal_id: str, key: str, value: Any, expected_version: int) -> VersionedValue:
        return await self.store.put_state(goal_id, key, value, expected_version)

    async def reset(self) -> None:
        await self.store.reset()
