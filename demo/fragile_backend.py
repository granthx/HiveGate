"""Deliberately fragile upstream used to demonstrate uncontrolled agent traffic.

The service has a hard concurrency ceiling, slows down under load, and exposes
a naive read-modify-write endpoint plus a fenced write endpoint. Its counters
are intentionally small and local so a benchmark can inspect them directly.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

READ_TOOLS = {"read", "get", "search", "fetch", "list"}


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


class BackendState:
    """Capacity-limited backend state, naive records, and counters."""

    def __init__(self, capacity: int = 4, delay_s: float = 0.01) -> None:
        self.capacity = capacity
        self.delay_s = delay_s
        self.active = 0
        self.peak = 0
        self.errors = 0
        self.calls = 0
        self.accepted = 0
        self.fencing_rejections = 0
        self.records: dict[str, int] = {"hot": 0, "secret": 0}
        self.last_fence: dict[str, int] = {}
        self.latencies_ms: list[float] = []
        self._lock = asyncio.Lock()

    def reset(self) -> None:
        """Clear counters and records between demo scenes."""

        self.active = 0
        self.peak = 0
        self.errors = 0
        self.calls = 0
        self.accepted = 0
        self.fencing_rejections = 0
        self.records = {"hot": 0, "secret": 0}
        self.last_fence = {}
        self.latencies_ms = []

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-safe view used by the dashboard and benchmark."""

        return {
            "capacity": self.capacity,
            "calls": self.calls,
            "accepted": self.accepted,
            "errors": self.errors,
            "active_concurrency": self.active,
            "peak_concurrency": self.peak,
            "p50_ms": round(_percentile(self.latencies_ms, 0.50), 3),
            "p99_ms": round(_percentile(self.latencies_ms, 0.99), 3),
            "fencing_rejections": self.fencing_rejections,
            "records": dict(self.records),
        }


def create_app(capacity: int = 4, delay_s: float = 0.01) -> FastAPI:
    """Create a fragile backend with fixed capacity and naive writes."""

    state = BackendState(capacity, delay_s)
    app = FastAPI(title="Fragile Backend")
    app.state.backend = state

    @app.post("/tools/{tool}")
    async def tool(tool: str, request: Request) -> JSONResponse:
        payload: dict[str, Any] = await request.json()
        started = time.perf_counter()
        state.calls += 1

        async with state._lock:
            if state.active >= state.capacity:
                state.errors += 1
                return JSONResponse(
                    {"status": "error", "reason": "over_capacity", "retry_after_ms": 25},
                    status_code=429,
                )
            state.active += 1
            state.accepted += 1
            state.peak = max(state.peak, state.active)

        try:
            # Load makes latency worse, but the hard ceiling above is what
            # actually refuses traffic once the backend is overwhelmed.
            await asyncio.sleep(delay_s * (1 + max(0, state.active - 1) * 0.15))

            if tool in READ_TOOLS:
                record = str(payload.get("record", "hot"))
                return JSONResponse(
                    {"status": "ok", "record": record, "value": state.records.get(record, 0)}
                )

            if tool == "write":
                # Naive read-modify-write. Concurrent writes intentionally lose updates.
                record = str(payload.get("record", "hot"))
                current = state.records.get(record, 0)
                await asyncio.sleep(delay_s)
                state.records[record] = current + int(payload.get("delta", 1))
                return JSONResponse(
                    {"status": "ok", "record": record, "value": state.records[record]}
                )

            if tool == "guarded_write":
                # A stale fencing token is rejected, so a writer that lost its
                # lease cannot overwrite a newer holder's result.
                record = str(payload.get("record", "hot"))
                token = int(payload.get("fencing_token", 0))
                if token <= state.last_fence.get(record, 0):
                    state.fencing_rejections += 1
                    return JSONResponse(
                        {"status": "conflict", "reason": "stale_fencing_token"},
                        status_code=409,
                    )
                state.last_fence[record] = token
                current = state.records.get(record, 0)
                await asyncio.sleep(delay_s)
                state.records[record] = current + int(payload.get("delta", 1))
                return JSONResponse(
                    {
                        "status": "ok",
                        "record": record,
                        "value": state.records[record],
                        "fencing_token": token,
                    }
                )

            if tool == "delete":
                record = str(payload.get("record", "hot"))
                state.records.pop(record, None)
                return JSONResponse({"status": "ok", "deleted": record})

            if tool == "refund":
                amount = float(payload.get("amount", 0))
                return JSONResponse({"status": "ok", "refunded": amount})

            return JSONResponse({"status": "ok", "tool": tool, "echo": payload})
        finally:
            elapsed = (time.perf_counter() - started) * 1000
            async with state._lock:
                state.active -= 1
                state.latencies_ms.append(elapsed)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics")
    async def metrics() -> dict[str, Any]:
        return state.snapshot()

    @app.get("/records")
    async def records() -> dict[str, int]:
        return dict(state.records)

    @app.post("/reset")
    async def reset() -> dict[str, str]:
        state.reset()
        return {"status": "ok"}

    return app


app = create_app()
