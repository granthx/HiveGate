"""store.py — Shared Storage Interface with Redis and In-Memory Fallback (Task B6).

Provides an abstract interface and concrete implementations for:
1. Expiring leased locks with monotonically increasing fencing tokens.
2. Goal-scoped optimistic concurrency CAS state.
3. Multi-replica safety: fencing tokens stay strictly monotonic and no lost updates occur.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("agent_gateway.store")


@dataclass
class Lease:
    """Current holder of a resource lease with a monotonic fencing token."""

    goal_id: str
    agent_id: str
    token: int
    expires_at: float


@dataclass
class VersionedValue:
    """A versioned value for compare-and-set optimistic concurrency."""

    value: Any
    version: int


class StateConflict(Exception):
    """Raised when a CAS put encounters a version mismatch."""

    def __init__(self, current_version: int) -> None:
        self.current_version = current_version
        super().__init__(f"State conflict: expected version does not match current version {current_version}")


class BaseStore(ABC):
    """Abstract storage interface for Agent Gateway state and coordination."""

    @abstractmethod
    async def acquire_lock(self, resource: str, goal_id: str, agent_id: str, ttl_ms: int) -> Lease | None:
        """Acquire a leased lock on a resource returning a monotonic fencing token."""

    @abstractmethod
    async def release_lock(self, resource: str, token: int) -> bool:
        """Release a leased lock if the token matches."""

    @abstractmethod
    async def is_lock_valid(self, resource: str, token: int) -> bool:
        """Check if a lease is active and matches the given fencing token."""

    @abstractmethod
    async def get_state(self, goal_id: str, key: str) -> VersionedValue | None:
        """Retrieve a versioned value."""

    @abstractmethod
    async def put_state(self, goal_id: str, key: str, value: Any, expected_version: int) -> VersionedValue:
        """Atomically set a value if expected_version matches current version, else raise StateConflict."""

    @abstractmethod
    async def reset(self) -> None:
        """Clear all stored state (used between test runs and demos)."""

    @abstractmethod
    async def close(self) -> None:
        """Close store connections."""


class InMemoryStore(BaseStore):
    """Process-local thread-safe in-memory store with monotonic fencing and CAS."""

    def __init__(self, shared_data: dict[str, Any] | None = None) -> None:
        # shared_data can be passed across instances to simulate multi-replica storage
        if shared_data is not None:
            self._data = shared_data
            self._lock = shared_data.setdefault("_lock", asyncio.Lock())
        else:
            self._data = {
                "leases": {},
                "tokens": {},
                "state": {},
            }
            self._lock = asyncio.Lock()

    async def acquire_lock(self, resource: str, goal_id: str, agent_id: str, ttl_ms: int) -> Lease | None:
        async with self._lock:
            now = time.monotonic()
            current: Lease | None = self._data["leases"].get(resource)
            if current and current.expires_at > now:
                return None
            next_token = self._data["tokens"].get(resource, 0) + 1
            self._data["tokens"][resource] = next_token
            lease = Lease(goal_id=goal_id, agent_id=agent_id, token=next_token, expires_at=now + (ttl_ms / 1000.0))
            self._data["leases"][resource] = lease
            return lease

    async def release_lock(self, resource: str, token: int) -> bool:
        async with self._lock:
            current: Lease | None = self._data["leases"].get(resource)
            if current and current.token == token:
                del self._data["leases"][resource]
                return True
            return False

    async def is_lock_valid(self, resource: str, token: int) -> bool:
        async with self._lock:
            current: Lease | None = self._data["leases"].get(resource)
            return bool(current and current.token == token and current.expires_at > time.monotonic())

    async def get_state(self, goal_id: str, key: str) -> VersionedValue | None:
        async with self._lock:
            return self._data["state"].get((goal_id, key))

    async def put_state(self, goal_id: str, key: str, value: Any, expected_version: int) -> VersionedValue:
        async with self._lock:
            current: VersionedValue | None = self._data["state"].get((goal_id, key))
            current_version = current.version if current else 0
            if expected_version != current_version:
                raise StateConflict(current_version)
            new_val = VersionedValue(value=value, version=current_version + 1)
            self._data["state"][(goal_id, key)] = new_val
            return new_val

    async def reset(self) -> None:
        async with self._lock:
            self._data["leases"].clear()
            self._data["tokens"].clear()
            self._data["state"].clear()

    async def close(self) -> None:
        pass


# Lua scripts for atomic Redis coordination
LUA_ACQUIRE_LOCK = """
local resource = KEYS[1]
local token_key = KEYS[2]
local goal_id = ARGV[1]
local agent_id = ARGV[2]
local ttl_ms = tonumber(ARGV[3])
local now_epoch_ms = tonumber(ARGV[4])

local current_raw = redis.call('GET', resource)
if current_raw then
    local current = cjson.decode(current_raw)
    if current.expires_at_ms > now_epoch_ms then
        return nil
    end
end

local token = redis.call('INCR', token_key)
local lease = {
    goal_id = goal_id,
    agent_id = agent_id,
    token = token,
    expires_at_ms = now_epoch_ms + ttl_ms
}
redis.call('SET', resource, cjson.encode(lease), 'PX', ttl_ms)
return cjson.encode(lease)
"""

LUA_RELEASE_LOCK = """
local resource = KEYS[1]
local token = tonumber(ARGV[1])

local current_raw = redis.call('GET', resource)
if not current_raw then
    return 0
end
local current = cjson.decode(current_raw)
if current.token == token then
    redis.call('DEL', resource)
    return 1
end
return 0
"""

LUA_CAS_PUT = """
local state_key = KEYS[1]
local expected_version = tonumber(ARGV[1])
local new_value_json = ARGV[2]

local current_raw = redis.call('GET', state_key)
local current_version = 0
if current_raw then
    local current = cjson.decode(current_raw)
    current_version = current.version
end

if expected_version ~= current_version then
    return {-1, current_version}
end

local next_version = current_version + 1
local new_record = {
    value = cjson.decode(new_value_json),
    version = next_version
}
redis.call('SET', state_key, cjson.encode(new_record))
return {1, next_version}
"""


class RedisStore(BaseStore):
    """Production Redis store with atomic Lua scripts for locks, fencing, and CAS."""

    def __init__(self, redis_client: Any) -> None:
        self.redis = redis_client

    async def acquire_lock(self, resource: str, goal_id: str, agent_id: str, ttl_ms: int) -> Lease | None:
        lock_key = f"gw:lock:{resource}"
        token_key = f"gw:seq:{resource}"
        now_epoch_ms = int(time.time() * 1000)

        raw = await self.redis.eval(
            LUA_ACQUIRE_LOCK,
            2,
            lock_key,
            token_key,
            goal_id,
            agent_id,
            str(ttl_ms),
            str(now_epoch_ms),
        )
        if not raw:
            return None
        data = json.loads(raw)
        return Lease(
            goal_id=data["goal_id"],
            agent_id=data["agent_id"],
            token=data["token"],
            expires_at=data["expires_at_ms"] / 1000.0,
        )

    async def release_lock(self, resource: str, token: int) -> bool:
        lock_key = f"gw:lock:{resource}"
        res = await self.redis.eval(LUA_RELEASE_LOCK, 1, lock_key, str(token))
        return bool(res == 1)

    async def is_lock_valid(self, resource: str, token: int) -> bool:
        lock_key = f"gw:lock:{resource}"
        raw = await self.redis.get(lock_key)
        if not raw:
            return False
        data = json.loads(raw)
        now_epoch_ms = int(time.time() * 1000)
        return bool(data.get("token") == token and data.get("expires_at_ms", 0) > now_epoch_ms)

    async def get_state(self, goal_id: str, key: str) -> VersionedValue | None:
        state_key = f"gw:state:{goal_id}:{key}"
        raw = await self.redis.get(state_key)
        if not raw:
            return None
        data = json.loads(raw)
        return VersionedValue(value=data["value"], version=data["version"])

    async def put_state(self, goal_id: str, key: str, value: Any, expected_version: int) -> VersionedValue:
        state_key = f"gw:state:{goal_id}:{key}"
        payload_json = json.dumps(value)
        res = await self.redis.eval(LUA_CAS_PUT, 1, state_key, str(expected_version), payload_json)
        code, ver = res[0], res[1]
        if code == -1:
            raise StateConflict(ver)
        return VersionedValue(value=value, version=ver)

    async def reset(self) -> None:
        # Scan and delete gateway keys
        keys = []
        async for k in self.redis.scan_iter("gw:*"):
            keys.append(k)
        if keys:
            await self.redis.delete(*keys)

    async def close(self) -> None:
        await self.redis.aclose()


async def create_store(redis_url: str | None = None) -> BaseStore:
    """Create a RedisStore if redis is configured and reachable, else fallback to InMemoryStore."""
    url = redis_url or os.getenv("REDIS_URL")
    if url:
        try:
            import redis.asyncio as aioredis
            client = aioredis.from_url(url, decode_responses=True)
            await client.ping()
            logger.info("Connected to Redis store at %s", url)
            return RedisStore(client)
        except Exception as exc:
            logger.warning("Failed to connect to Redis (%s); falling back to InMemoryStore", exc)

    return InMemoryStore()

