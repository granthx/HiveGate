"""FastAPI application and ordered request pipeline for Agent Gateway."""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import httpx
from fastapi import FastAPI, Header, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from .admission import AdmissionRejected, AdaptiveLimiter
from .budgets import BudgetDenied, BudgetManager, LoopDetected
from .config import GatewayConfig
from .dedup import Singleflight, call_key
from .forward import CircuitOpen, Forwarder
from .locks import LockManager
from .metrics import Metrics
from .models import (
    CallRequest,
    CallResponse,
    GoalCreateRequest,
    GoalResponse,
    GoalTracesResponse,
    LockAcquireRequest,
    LockReleaseRequest,
    StateWriteRequest,
    TargetRegisterResponse,
    TraceNode,
    UpstreamTarget,
)
from .policy import DEFAULT_POLICY_PATH, PolicyEngine
from .scheduler import FairScheduler, QueueOverflow
from .state import StateConflict, StateStore
from .store import BaseStore, InMemoryStore, create_store
from .traces import TraceStore

READ_TOOLS = {"read", "get", "search", "fetch", "list"}
DISPATCH_EVENT_MIN_MS = 100.0
STARVATION_MIN_MS = 1000.0


class GatewayRuntime:
    """All stateful components for one gateway process."""

    def __init__(
        self,
        upstream_client: httpx.AsyncClient,
        policy: PolicyEngine | None = None,
        config: GatewayConfig | None = None,
        store: BaseStore | None = None,
    ) -> None:
        self.config = config or GatewayConfig.from_env()
        self.store = store or InMemoryStore()
        self.policy = policy or PolicyEngine.from_file(os.getenv("AGENT_GATEWAY_POLICY") or DEFAULT_POLICY_PATH)
        self.budgets = BudgetManager()
        self.dedup = Singleflight()
        self.admission = AdaptiveLimiter(
            initial=self.config.admission_initial,
            maximum=self.config.admission_maximum,
            queue_limit=self.config.admission_queue_limit,
        )
        self.scheduler = FairScheduler(self.admission)
        self.locks = LockManager(self.store)
        self.state = StateStore(self.store)
        self.traces = TraceStore()
        self.metrics = Metrics()
        self.forwarder = Forwarder(
            upstream_client,
            timeout_s=self.config.upstream_timeout_s,
            retries=self.config.upstream_retries,
        )
        self.upstreams: dict[str, UpstreamTarget] = {}
        self.started_at = time.time()

    def register_target(self, target: UpstreamTarget) -> None:
        """Register a dynamic upstream target."""
        self.upstreams[target.target_id] = target

    async def reset(self) -> None:
        """Reset mutable demo state while keeping SSE subscribers alive."""

        self.policy.reset()
        self.budgets = BudgetManager()
        self.dedup = Singleflight()
        await self.locks.reset()
        await self.state.reset()
        self.admission.reset()
        self.scheduler.reset()
        self.forwarder.reset()
        self.upstreams.clear()
        await self.traces.reset()
        await self.metrics.reset()

    async def proxy_call(
        self,
        target_id: str,
        method: str,
        path: str,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        goal_id: str = "proxy-default",
        agent_id: str = "proxy-agent",
    ) -> tuple[int, dict[str, str], bytes, bool]:
        """Execute a proxied HTTP call through admission control and singleflight dedup."""
        target = self.upstreams.get(target_id)
        if target is None:
            raise KeyError(f"Unknown target_id '{target_id}'")

        if method.upper() not in [m.upper() for m in target.allowed_methods]:
            raise PermissionError(f"Method '{method}' not allowed for target '{target_id}'")

        is_idempotent = method.upper() in {"GET", "HEAD"}
        # Build cache / singleflight key
        content_hash = hash(content) if content else 0
        params_key = tuple(sorted((params or {}).items()))
        key = f"proxy:{target_id}:{method.upper()}:{path}:{params_key}:{content_hash}"

        async def _execute() -> tuple[int, dict[str, str], bytes]:
            async def _forward_op() -> tuple[int, dict[str, str], bytes]:
                resp = await self.forwarder.forward_request(
                    target=target,
                    method=method,
                    subpath=path,
                    content=content,
                    headers=headers,
                    params=params,
                    idempotent=is_idempotent,
                )
                filtered_headers = {
                    k: v
                    for k, v in resp.headers.items()
                    if k.lower() not in {"content-length", "content-encoding", "transfer-encoding", "connection"}
                }
                return resp.status_code, filtered_headers, resp.content

            return await self.admission.run(_forward_op)

        result, shared = await self.dedup.run(key, _execute, cache_read=is_idempotent)
        status_code, resp_headers, body = result
        if shared:
            await self.metrics.record("deduplicated", goal_id=goal_id, tool=f"proxy:{target_id}")
            resp_headers["x-gateway-dedup"] = "coalesced"
        return status_code, resp_headers, body, shared

    async def call(self, request: CallRequest) -> CallResponse:
        call_id = uuid.uuid4().hex
        call_started = time.perf_counter()
        depth = 0

        async def _finish(response: CallResponse) -> CallResponse:
            # The trace keeps the internal call_id for every outcome, but only
            # successful calls expose it to clients (it is a valid parent id).
            duration_ms = (time.perf_counter() - call_started) * 1000
            await self.traces.record(
                goal_id=request.goal_id,
                call_id=call_id,
                agent_id=request.agent_id,
                tool=request.tool,
                status=response.status,
                parent_call_id=request.parent_call_id,
                depth=response.depth if response.depth is not None else depth,
                duration_ms=round(duration_ms, 2),
                reason=response.reason,
            )
            return response

        usage = self.budgets.get(request.goal_id)
        if usage is None:
            await self.metrics.record("budget_denied", reason="unknown_goal", goal_id=request.goal_id)
            return await _finish(CallResponse(status="budget_exceeded", reason="unknown_goal", limit="unknown_goal"))

        if request.parent_call_id and request.parent_call_id not in usage.call_depths:
            await self.metrics.record(
                "call_tree_invalid",
                reason="unknown_parent",
                goal_id=request.goal_id,
                parent_call_id=request.parent_call_id,
            )
            return await _finish(CallResponse(status="denied", reason="unknown_parent", depth=0))

        depth = usage.call_depths.get(request.parent_call_id, -1) + 1 if request.parent_call_id else 0
        fingerprint = call_key(request.tool, request.payload)
        try:
            self.budgets.reserve(
                request.goal_id,
                call_id,
                depth,
                request.estimated_cost,
                fingerprint=fingerprint,
            )
        except LoopDetected:
            await self.metrics.record("loop_detected", goal_id=request.goal_id, agent_id=request.agent_id)
            return await _finish(CallResponse(status="denied", reason="loop_detected", limit="loop_detected", depth=depth))
        except BudgetDenied as exc:
            event = "depth_denied" if exc.limit == "max_depth" else "budget_cancelled"
            await self.metrics.record(event, reason=exc.limit, goal_id=request.goal_id)
            return await _finish(CallResponse(status="budget_exceeded", reason=exc.limit, limit=exc.limit, depth=depth))

        decision = await self.policy.evaluate(request)
        if decision.pending:
            await self.metrics.record(
                "approval_pending",
                goal_id=request.goal_id,
                agent_id=request.agent_id,
                tool=request.tool,
                approval_id=decision.approval_id,
            )
            return await _finish(CallResponse(
                status="pending_approval",
                reason=decision.reason,
                approval_id=decision.approval_id,
                depth=depth,
            ))
        if not decision.allowed:
            await self.metrics.record(
                "policy_denied",
                goal_id=request.goal_id,
                agent_id=request.agent_id,
                tool=request.tool,
                reason=decision.reason,
            )
            return await _finish(CallResponse(status="denied", reason=decision.reason, depth=depth))

        idempotent = request.idempotency_key is not None or request.tool in READ_TOOLS
        key = request.idempotency_key or fingerprint
        if not idempotent:
            key = f"{key}:{call_id}"

        async def operation() -> dict[str, Any]:
            started = time.perf_counter()
            await self.metrics.start_call()
            try:
                async with self.scheduler.slot(request.goal_id, usage.budget.weight) as queued:
                    wait_ms = (time.perf_counter() - started) * 1000
                    if wait_ms >= DISPATCH_EVENT_MIN_MS:
                        await self.metrics.record(
                            "scheduler_dispatched",
                            goal_id=request.goal_id,
                            wait_ms=round(wait_ms, 1),
                            queue_len=queued.queue_len_at_grant,
                        )
                    if wait_ms >= STARVATION_MIN_MS:
                        await self.metrics.record(
                            "starvation_detected",
                            goal_id=request.goal_id,
                            reason="queue_wait_exceeded",
                            wait_ms=round(wait_ms, 1),
                        )
                    response = await self.admission.run(
                        lambda: self.forwarder.call(request.tool, request.payload, idempotent=idempotent)
                    )
                if response.status_code >= 400:
                    raise RuntimeError(f"upstream_status_{response.status_code}")
                return response.json()
            except Exception:
                await self.metrics.finish_call((time.perf_counter() - started) * 1000, False)
                raise
            else:
                await self.metrics.finish_call((time.perf_counter() - started) * 1000, True)

        try:
            result, shared = await self.dedup.run(key, operation, cache_read=idempotent)
        except QueueOverflow:
            await self.metrics.record("throttled", goal_id=request.goal_id, reason="fair_queue_full")
            return await _finish(CallResponse(status="throttled", reason="fair_queue_full", retry_after_ms=100, depth=depth))
        except AdmissionRejected:
            await self.metrics.record("throttled", goal_id=request.goal_id, reason="queue_full")
            return await _finish(CallResponse(status="throttled", reason="queue_full", retry_after_ms=100, depth=depth))
        except CircuitOpen:
            await self.metrics.record("upstream_error", reason="circuit_open", goal_id=request.goal_id)
            return await _finish(CallResponse(status="error", reason="circuit_open", retry_after_ms=250, depth=depth))
        except Exception as exc:
            await self.metrics.record(
                "upstream_error",
                reason=str(exc),
                goal_id=request.goal_id,
                agent_id=request.agent_id,
            )
            return await _finish(CallResponse(
                status="error",
                reason="upstream_unavailable",
                retry_after_ms=50,
                depth=depth,
            ))

        if shared:
            await self.metrics.record("deduplicated", goal_id=request.goal_id, tool=request.tool)
        await self.metrics.record(
            "call_completed",
            call_id=call_id,
            parent_call_id=request.parent_call_id,
            depth=depth,
            goal_id=request.goal_id,
            agent_id=request.agent_id,
            tool=request.tool,
        )
        return await _finish(CallResponse(status="ok", call_id=call_id, result=result, depth=depth))


def create_app(
    upstream_client: httpx.AsyncClient | None = None,
    *,
    policy: PolicyEngine | None = None,
    config: GatewayConfig | None = None,
    store: BaseStore | None = None,
) -> FastAPI:
    """Create the gateway app, optionally with an injected async HTTP client."""

    owns_client = upstream_client is None
    client = upstream_client or httpx.AsyncClient(
        base_url=os.getenv("AGENT_GATEWAY_UPSTREAM", "http://127.0.0.1:9001")
    )
    runtime = GatewayRuntime(client, policy=policy, config=config, store=store)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        if owns_client:
            await client.aclose()
        await runtime.forwarder.aclose()
        await runtime.store.close()

    app = FastAPI(title="Agent Gateway", lifespan=lifespan)
    app.state.runtime = runtime

    @app.get("/health")
    @app.get("/v1/health")
    async def health() -> dict[str, Any]:
        uptime = round(time.time() - runtime.started_at, 2)
        return {"status": "ok", "uptime_s": uptime}

    @app.get("/ready")
    @app.get("/v1/ready")
    async def ready() -> JSONResponse:
        store_ok = True
        try:
            await runtime.store.get_state("ready_check", "test")
        except Exception:
            store_ok = False
        status_code = 200 if store_ok else 503
        return JSONResponse(
            {
                "status": "ready" if store_ok else "degraded",
                "store_connected": store_ok,
                "policy_rules": len(runtime.policy.rules),
                "upstreams_registered": len(runtime.upstreams),
                "failure_policy": runtime.config.failure_policy,
            },
            status_code=status_code,
        )

    @app.get("/metrics")
    async def prometheus_metrics() -> Response:
        snapshot = runtime.metrics.snapshot()
        active = runtime.admission.active
        waiting = runtime.admission.waiting
        lines = [
            "# HELP agent_gateway_calls_total Total calls processed by Agent Gateway",
            "# TYPE agent_gateway_calls_total counter",
            f'agent_gateway_calls_total {snapshot.get("calls", 0)}',
            "# HELP agent_gateway_upstream_errors_total Total upstream 429 or 5xx errors",
            "# TYPE agent_gateway_upstream_errors_total counter",
            f'agent_gateway_upstream_errors_total {snapshot.get("upstream_errors", 0)}',
            "# HELP agent_gateway_calls_avoided_total Total backend calls avoided via singleflight",
            "# TYPE agent_gateway_calls_avoided_total counter",
            f'agent_gateway_calls_avoided_total {snapshot.get("calls_avoided", 0)}',
            "# HELP agent_gateway_lost_updates_total Total lost updates detected by CAS",
            "# TYPE agent_gateway_lost_updates_total counter",
            f'agent_gateway_lost_updates_total {snapshot.get("lost_updates", 0)}',
            "# HELP agent_gateway_concurrency_active Current active in-flight calls to upstream",
            "# TYPE agent_gateway_concurrency_active gauge",
            f'agent_gateway_concurrency_active {active}',
            "# HELP agent_gateway_queue_waiting Current waiting calls in admission queue",
            "# TYPE agent_gateway_queue_waiting gauge",
            f'agent_gateway_queue_waiting {waiting}',
        ]
        return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

    @app.post("/v1/targets", response_model=TargetRegisterResponse)
    async def register_upstream_target(target: UpstreamTarget) -> TargetRegisterResponse:
        runtime.register_target(target)
        return TargetRegisterResponse(status="ok", target=target)

    @app.get("/v1/targets")
    async def list_upstream_targets() -> dict[str, Any]:
        return {"status": "ok", "targets": runtime.upstreams}

    @app.api_route(
        "/v1/proxy/{target_id}/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"],
    )
    async def proxy_to_target(
        target_id: str,
        path: str,
        request: Request,
    ) -> Response:
        try:
            body = await request.body()
            goal_id = request.headers.get("X-Goal-ID", "proxy-goal")
            agent_id = request.headers.get("X-Agent-ID", "proxy-agent")
            status_code, headers, content, shared = await runtime.proxy_call(
                target_id=target_id,
                method=request.method,
                path=path,
                content=body if body else None,
                headers=dict(request.headers),
                params=dict(request.query_params),
                goal_id=goal_id,
                agent_id=agent_id,
            )
            return Response(content=content, status_code=status_code, headers=headers)
        except KeyError:
            return JSONResponse({"status": "not_found", "reason": f"target '{target_id}' not found"}, status_code=404)
        except PermissionError as e:
            return JSONResponse({"status": "denied", "reason": str(e)}, status_code=403)
        except AdmissionRejected:
            return JSONResponse({"status": "throttled", "reason": "queue_full", "retry_after_ms": 100}, status_code=429)
        except Exception as exc:
            return JSONResponse({"status": "error", "reason": str(exc)}, status_code=502)

    @app.post("/v1/goals", response_model=GoalResponse)
    async def create_goal(request: GoalCreateRequest) -> GoalResponse:
        goal_id = request.goal_id or uuid.uuid4().hex
        budget = request.model_copy(update={"goal_id": None})
        runtime.budgets.create(goal_id, budget)
        return GoalResponse(goal_id=goal_id, budget=budget)

    @app.post("/v1/call", response_model=CallResponse)
    async def call(request: CallRequest) -> CallResponse:
        return await runtime.call(request)

    @app.get("/v1/metrics")
    async def metrics() -> dict[str, Any]:
        return {**runtime.metrics.snapshot(), "admission": runtime.admission.snapshot(), "scheduler": runtime.scheduler.snapshot()}

    @app.get("/v1/events")
    async def events() -> StreamingResponse:
        async def stream() -> AsyncIterator[str]:
            async for event in runtime.metrics.subscribe():
                yield f"data: {json.dumps(event)}\n\n"

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.post("/v1/reset")
    async def reset_gateway() -> dict[str, str]:
        await runtime.reset()
        return {"status": "ok"}

    @app.get("/v1/traces", response_model=list[str])
    async def list_traces() -> list[str]:
        return await runtime.traces.goals()

    @app.get("/v1/traces/{goal_id}", response_model=GoalTracesResponse)
    async def get_goal_traces(goal_id: str) -> GoalTracesResponse:
        return await runtime.traces.get_tree(goal_id)

    @app.get("/v1/approvals")
    async def approvals() -> dict[str, Any]:
        return {"status": "ok", "approvals": [item.public() for item in runtime.policy.approvals.pending()]}

    @app.get("/v1/approvals/{approval_id}")
    async def get_approval(approval_id: str) -> JSONResponse:
        approval = runtime.policy.approvals.get(approval_id)
        if approval is None:
            return JSONResponse({"status": "not_found", "reason": "unknown_approval"}, status_code=404)
        return JSONResponse({"status": "ok", "approval": approval.public()})

    @app.post("/v1/approvals/{approval_id}/approve")
    async def approve(approval_id: str) -> JSONResponse:
        approval = runtime.policy.approvals.approve(approval_id)
        if approval is None:
            return JSONResponse(
                {"status": "denied", "reason": "approval_not_pending"},
                status_code=409,
            )
        await runtime.metrics.record(
            "approval_approved",
            approval_id=approval_id,
            goal_id=approval.goal_id,
            agent_id=approval.agent_id,
            tool=approval.tool,
        )
        return JSONResponse({"status": "ok", "approval": approval.public()})

    @app.post("/v1/locks/acquire")
    async def acquire_lock(
        request: LockAcquireRequest,
        x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    ) -> dict[str, Any]:
        tenant = (x_tenant_id or "default").strip()
        scoped_resource = f"{tenant}:{request.resource}"
        scoped_goal_id = f"{tenant}:{request.goal_id}"
        lease = await runtime.locks.acquire(scoped_resource, scoped_goal_id, request.agent_id, request.ttl_ms)
        if lease is None:
            return {"status": "denied", "reason": "lock_unavailable", "granted": False}
        await runtime.metrics.record("lock_acquired", resource=request.resource, goal_id=request.goal_id)
        return {"status": "ok", "granted": True, "fencing_token": lease.token, "expires_at": lease.expires_at}

    @app.post("/v1/locks/release")
    async def release_lock(
        request: LockReleaseRequest,
        x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    ) -> dict[str, Any]:
        tenant = (x_tenant_id or "default").strip()
        scoped_resource = f"{tenant}:{request.resource}"
        released = await runtime.locks.release(scoped_resource, request.fencing_token)
        if released:
            await runtime.metrics.record("lock_released", resource=request.resource)
        return {"status": "ok" if released else "denied", "released": released}

    @app.get("/v1/state/{goal_id}/{key}")
    async def get_state(
        goal_id: str,
        key: str,
        x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    ) -> JSONResponse:
        tenant = (x_tenant_id or "default").strip()
        scoped_goal_id = f"{tenant}:{goal_id}"
        value = await runtime.state.get(scoped_goal_id, key)
        if value is None:
            return JSONResponse({"status": "ok", "value": None, "version": 0})
        return JSONResponse({"status": "ok", "value": value.value, "version": value.version})

    @app.put("/v1/state/{goal_id}/{key}")
    async def put_state(
        goal_id: str,
        key: str,
        request: StateWriteRequest,
        if_match: str | None = Header(default=None),
        x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    ) -> JSONResponse:
        if if_match is None:
            return JSONResponse({"status": "denied", "reason": "if_match_required"}, status_code=428)
        tenant = (x_tenant_id or "default").strip()
        scoped_goal_id = f"{tenant}:{goal_id}"
        try:
            version = await runtime.state.put(scoped_goal_id, key, request.value, int(if_match))
        except (ValueError, StateConflict) as exc:
            current = exc.current_version if isinstance(exc, StateConflict) else 0
            await runtime.metrics.record("lost_update", goal_id=goal_id, key=key)
            return JSONResponse(
                {"status": "conflict", "reason": "version_mismatch", "version": current},
                status_code=409,
            )
        return JSONResponse({"status": "ok", "value": version.value, "version": version.version})

    return app


app = create_app()
