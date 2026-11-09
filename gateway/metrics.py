"""Metrics counters, latency summaries, and live events for the dashboard."""

from __future__ import annotations

import asyncio
import time
from collections import Counter
from statistics import quantiles
from typing import Any, AsyncIterator


class Metrics:
    """Small in-memory metrics registry suitable for the local demo."""

    def __init__(self) -> None:
        self._counts: Counter[str] = Counter()
        self._latencies_ms: list[float] = []
        self._active = 0
        self._peak = 0
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    async def record(self, event: str, **fields: Any) -> None:
        self._counts[event] += 1
        await self.publish({"event": event, "ts": time.time(), **fields})

    async def start_call(self) -> None:
        self._active += 1
        self._peak = max(self._peak, self._active)

    async def finish_call(self, latency_ms: float, success: bool) -> None:
        self._active = max(0, self._active - 1)
        self._latencies_ms.append(latency_ms)
        self._counts["success" if success else "failure"] += 1

    async def publish(self, event: dict[str, Any]) -> None:
        for queue in tuple(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    async def reset(self) -> None:
        """Clear this run's counters without dropping SSE subscribers."""

        self._counts.clear()
        self._latencies_ms.clear()
        self._active = 0
        self._peak = 0
        await self.publish({"event": "reset", "ts": time.time()})

    def snapshot(self) -> dict[str, Any]:
        values = sorted(self._latencies_ms)
        p50 = values[len(values) // 2] if values else 0.0
        p99 = values[min(len(values) - 1, int(len(values) * 0.99))] if values else 0.0
        if len(values) >= 2:
            p50 = quantiles(values, n=100, method="inclusive")[49]
            p99 = quantiles(values, n=100, method="inclusive")[98]
        counters = dict(self._counts)
        completed = counters.get("success", 0) + counters.get("failure", 0)
        return {
            "counters": counters,
            "success_rate": round(counters.get("success", 0) / completed, 4) if completed else 0.0,
            "latency_ms": {"p50": round(p50, 3), "p99": round(p99, 3)},
            "gateway_concurrency": {"active": self._active, "peak": self._peak},
        }

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._subscribers.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers.discard(queue)
