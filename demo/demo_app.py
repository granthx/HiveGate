"""One-command demo harness: two backends, the gateway, dashboard, and scenes."""

from __future__ import annotations

import asyncio
import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from demo.scenes import (
    PRICE_PER_CALL_USD,
    SCENE_DEFINITIONS,
    SceneHarness,
    create_harness,
    run_scene,
)
from gateway.models import CallRequest


class SceneRunRequest(BaseModel):
    """Options for a dashboard-triggered scene run."""

    seed: int = 7


class EventBus:
    """Fan-out queue for the dashboard's server-sent event stream."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    def publish(self, event_type: str, data: dict[str, Any]) -> None:
        event = {"type": event_type, "ts": time.time(), "data": data}
        for queue in tuple(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=200)
        self._subscribers.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers.discard(queue)


def create_demo_app() -> FastAPI:
    """Build the single-process demo used by ``make demo``."""

    harness: SceneHarness = create_harness()
    bus = EventBus()
    scene_lock = asyncio.Lock()
    demo_state: dict[str, Any] = {"running": None, "last_results": {}}

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await harness.close()

    app = FastAPI(title="Agent Gateway Demo", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.harness = harness
    app.state.bus = bus

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "running": demo_state["running"],
            "gateway": harness.gateway.state.runtime.metrics.snapshot(),
        }

    @app.get("/demo/scenes")
    async def scenes() -> dict[str, Any]:
        return {
            "status": "ok",
            "scenes": SCENE_DEFINITIONS,
            "price_per_call_usd": PRICE_PER_CALL_USD,
            "swarm": "simulated",
        }

    @app.get("/demo/snapshot")
    async def snapshot() -> dict[str, Any]:
        runtime = harness.gateway.state.runtime
        return {
            "status": "ok",
            "direct": harness.direct_backend.state.backend.snapshot(),
            "protected": harness.protected_backend.state.backend.snapshot(),
            "gateway": runtime.metrics.snapshot(),
            "admission": runtime.admission.snapshot(),
            "running": demo_state["running"],
            "last_results": demo_state["last_results"],
        }

    @app.post("/demo/scenes/{scene_id}")
    async def run(scene_id: str, request: SceneRunRequest) -> JSONResponse:
        if scene_id not in {item["id"] for item in SCENE_DEFINITIONS}:
            raise HTTPException(status_code=404, detail={"status": "error", "reason": "unknown_scene"})
        if scene_lock.locked():
            return JSONResponse(
                {"status": "busy", "reason": "scene_running", "retry_after_ms": 250},
                status_code=409,
            )
        async with scene_lock:
            demo_state["running"] = scene_id
            try:
                result = await run_scene(scene_id, request.seed, harness, publish=bus.publish)
            except Exception as exc:  # pragma: no cover - surfaced to the dashboard
                bus.publish("scene_error", {"scene": scene_id, "reason": type(exc).__name__})
                return JSONResponse(
                    {"status": "error", "reason": "scene_failed", "detail": type(exc).__name__},
                    status_code=500,
                )
            finally:
                demo_state["running"] = None
            demo_state["last_results"][scene_id] = result
            bus.publish("scene_result", result)
            return JSONResponse(result)

    @app.post("/demo/record_run")
    async def record_external_run(request: Request) -> JSONResponse:
        """Accept a live multi-agent project run summary so the :8000 dashboard displays it."""
        payload: dict[str, Any] = await request.json()
        run_id = str(payload.get("scene") or payload.get("project_id") or "external")
        demo_state["last_results"][run_id] = payload
        bus.publish("scene_result", payload)
        return JSONResponse({"status": "ok", "recorded": run_id})

    @app.get("/demo/approvals")
    async def approvals() -> dict[str, Any]:
        runtime = harness.gateway.state.runtime
        return {
            "status": "ok",
            "approvals": [item.public() for item in runtime.policy.approvals.pending()],
        }

    @app.post("/demo/approvals/{approval_id}/approve")
    async def approve(approval_id: str) -> JSONResponse:
        runtime = harness.gateway.state.runtime
        approval = runtime.policy.approvals.get(approval_id)
        if approval is None:
            return JSONResponse(
                {"status": "not_found", "reason": "unknown_approval"},
                status_code=404,
            )
        if approval.status != "pending":
            return JSONResponse(
                {"status": "denied", "reason": "approval_not_pending"},
                status_code=409,
            )
        runtime.policy.approvals.approve(approval_id)
        result = await runtime.call(
            CallRequest(
                goal_id=approval.goal_id,
                agent_id=approval.agent_id,
                tool=approval.tool,
                payload=approval.payload,
                approval_id=approval_id,
            )
        )
        payload = {
            "approval_id": approval_id,
            "status": result.status,
            "result": result.result,
            "reason": result.reason,
        }
        bus.publish("approval_resolved", payload)
        return JSONResponse({"status": "ok", "approval_id": approval_id, "call": result.model_dump()})

    @app.get("/demo/events")
    async def events() -> StreamingResponse:
        async def stream() -> AsyncIterator[str]:
            async for event in bus.subscribe():
                yield f"data: {json.dumps(event)}\n\n"

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # Mounting keeps the real gateway API available under /gateway while the
    # dashboard stays same-origin (no CORS or extra ports for the stage demo).
    app.mount("/direct-backend", harness.direct_backend)
    app.mount("/backend", harness.protected_backend)
    app.mount("/gateway", harness.gateway)
    dashboard_dir = Path(__file__).resolve().parent / "dashboard"
    if not dashboard_dir.is_dir():
        dashboard_dir = Path(__file__).resolve().parent.parent / "test project" / "ui"
    if dashboard_dir.is_dir():
        app.mount(
            "/",
            StaticFiles(directory=dashboard_dir, html=True),
            name="dashboard",
        )
    return app


app = create_demo_app()
