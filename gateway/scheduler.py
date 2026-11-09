"""Weighted deficit round-robin queue across goals, in front of admission.

One goal flooding calls must not starve another goal that is waiting for an
upstream slot. Calls park here per goal and are released one at a time in
weighted round-robin order, so each goal receives roughly ``weight`` dispatches
per cycle regardless of how many calls it has queued.

The queue is in-memory for one process, like the rest of gateway state. There
is no background task and no blocking work: releases happen synchronously when
a call leaves its slot or when a new call arrives.
"""

from __future__ import annotations

import asyncio
import time
from collections import Counter, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, AsyncIterator

if TYPE_CHECKING:
    from .admission import AdaptiveLimiter


class QueueOverflow(Exception):
    """Raised when the fair queue has no room for another waiting call."""

    def __init__(self, scope: str) -> None:
        self.scope = scope
        super().__init__(scope)


@dataclass(eq=False)
class SlotEntry:
    """One queued admission attempt for a single call."""

    goal_id: str
    weight: int
    enqueued_at: float = field(default_factory=time.monotonic)
    event: asyncio.Event = field(default_factory=asyncio.Event)
    granted_at: float | None = None
    queue_len_at_grant: int | None = None

    def elapsed_ms(self) -> float:
        started = self.granted_at if self.granted_at is not None else time.monotonic()
        return (started - self.enqueued_at) * 1000


class FairScheduler:
    """Deficit round-robin across goals with FIFO order inside a goal."""

    def __init__(
        self,
        limiter: AdaptiveLimiter,
        *,
        max_queue: int = 512,
        per_goal_limit: int = 256,
        history_limit: int = 512,
    ) -> None:
        self._limiter = limiter
        self.max_queue = max_queue
        self.per_goal_limit = per_goal_limit
        self.history_limit = history_limit
        self._entries: dict[str, deque[SlotEntry]] = {}
        # Positive look: (goal_id, remaining quota in this round).
        self._order: deque[tuple[str, int]] = deque()
        self._in_order: set[str] = set()
        self._waiting = 0
        self._granted = 0
        self.dispatched: Counter[str] = Counter()
        self.history: deque[str] = deque(maxlen=history_limit)

    @asynccontextmanager
    async def slot(self, goal_id: str, weight: int = 1) -> AsyncIterator[SlotEntry]:
        """Wait for a weighted round-robin turn, then hold one upstream slot."""

        entry = self._enqueue(goal_id, weight)
        try:
            self._dispatch()
            try:
                await entry.event.wait()
            except asyncio.CancelledError:
                self._remove(entry)
                self._dispatch()
                raise
            yield entry
        finally:
            if entry.granted_at is not None:
                self._granted = max(0, self._granted - 1)
            self._dispatch()

    def _enqueue(self, goal_id: str, weight: int) -> SlotEntry:
        queue = self._entries.get(goal_id)
        if self._waiting >= self.max_queue or (queue and len(queue) >= self.per_goal_limit):
            if queue and len(queue) >= self.per_goal_limit:
                raise QueueOverflow(f"per_goal:{goal_id}")
            raise QueueOverflow("global")
        if queue is None:
            queue = self._entries[goal_id] = deque()
        if goal_id not in self._in_order:
            self._in_order.add(goal_id)
            self._order.append((goal_id, max(1, weight)))
        entry = SlotEntry(goal_id=goal_id, weight=max(1, weight))
        queue.append(entry)
        self._waiting += 1
        return entry

    def _dispatch(self) -> None:
        """Grant queued calls while admission capacity is free, in DRR order."""

        while self._granted < self._limiter.limit and self._waiting:
            picked = self._next_goal()
            if picked is None:
                return
            goal_id, remaining = picked
            self._order.popleft()
            queue = self._entries[goal_id]
            entry = queue.popleft()
            if queue:
                self._order.append((goal_id, remaining - 1))
            else:
                del self._entries[goal_id]
                self._in_order.discard(goal_id)
            self._waiting -= 1
            entry.granted_at = time.monotonic()
            entry.queue_len_at_grant = self._waiting
            self._granted += 1
            self.dispatched[goal_id] += 1
            self.history.append(goal_id)
            entry.event.set()

    def _next_goal(self) -> tuple[str, int] | None:
        """Pick the next goal via deficit round-robin, or None if nothing waits."""

        while self._order:
            goal_id, remaining = self._order[0]
            queue = self._entries.get(goal_id)
            if not queue:
                self._order.popleft()
                self._in_order.discard(goal_id)
                continue
            if remaining <= 0:
                # Quota spent: move to the back of the round with a fresh quantum.
                self._order.popleft()
                self._order.append((goal_id, queue[0].weight))
                continue
            return goal_id, remaining
        return None

    def _remove(self, entry: SlotEntry) -> None:
        if entry.granted_at is not None:
            return
        queue = self._entries.get(entry.goal_id)
        if queue and entry in queue:
            queue.remove(entry)
            if not queue:
                del self._entries[entry.goal_id]
                self._in_order.discard(entry.goal_id)
            self._waiting -= 1

    def reset(self) -> None:
        """Drop all queued and granted state (used between demo runs)."""

        for queue in self._entries.values():
            for entry in queue:
                entry.event.set()
        self._entries.clear()
        self._order.clear()
        self._in_order.clear()
        self._waiting = 0
        self._granted = 0
        self.dispatched.clear()
        self.history.clear()

    def snapshot(self) -> dict[str, Any]:
        return {
            "waiting": self._waiting,
            "active": self._granted,
            "limit": self._limiter.limit,
            "per_goal_waiting": {goal: len(queue) for goal, queue in self._entries.items() if queue},
            "dispatched": dict(self.dispatched),
            "max_queue": self.max_queue,
            "per_goal_limit": self.per_goal_limit,
        }
