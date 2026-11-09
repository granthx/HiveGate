"""test_gateway_core.py — Gateway Core Control Plane & Coordination Test Suite.

Compiled comprehensive test suite covering:
1. Adaptive Limiter & Queue Admission Control
2. Goal Budgeting, Depth Boundaries, and Loop Detection
3. Singleflight Deduplication & Short-TTL Caching
4. Coordination: Monotonic Fencing Tokens, CAS Versioned State & Multi-Replica Safety
5. YAML Policy Engine, Agent Write Quotas, Approvals & Payload Fingerprinting
6. Weighted Fair Queue Scheduler (Starvation Prevention & Concurrency Grants)
7. Trace Tree Hierarchy & Audit Log Inspection
8. Python SDK Client & @tool Invocations
9. Public Gateway REST API Endpoints, Health/Readiness & Prometheus /metrics
10. Dynamic Upstream Targets & Reverse Proxy Routing
11. Demo Scene Workloads & Event Stream Verification
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
from httpx import ASGITransport, AsyncClient
import pytest
from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent
TEST_PROJECT_DIR = ROOT_DIR / "test project"
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(TEST_PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(TEST_PROJECT_DIR))

from demo.fragile_backend import create_app as create_backend
from demo.demo_app import create_demo_app
from demo.scenes import SCENE_DEFINITIONS, SceneHarness, create_harness, run_fairness, run_scene
from demo.swarm import SwarmCall, build_read_workload, build_workload
from gateway.admission import AdaptiveLimiter, AdmissionRejected
from gateway.budgets import BudgetDenied, BudgetManager, LoopDetected
from gateway.config import GatewayConfig
from gateway.dedup import Singleflight
from gateway.forward import Forwarder
from gateway.locks import LockManager
from gateway.main import create_app as create_gateway
from gateway.models import CallRequest, GoalBudget, UpstreamTarget
from gateway.policy import PolicyEngine
from gateway.scheduler import FairScheduler, QueueOverflow
from gateway.state import StateStore
from gateway.store import InMemoryStore, StateConflict
from sdk.client import GatewayClient, GatewayError, langgraph_tool


# ===========================================================================
# 1. Adaptive Limiter & Admission Control
# ===========================================================================

class TestAdmissionControl:
    """Tests for bounded adaptive concurrency and admission queueing."""

    @pytest.mark.asyncio
    async def test_admission_never_exceeds_limit_and_shrinks_on_error(self) -> None:
        limiter = AdaptiveLimiter(initial=2, maximum=2, queue_limit=10)
        active = 0
        peak = 0
        lock = asyncio.Lock()

        async def operation() -> int:
            nonlocal active, peak
            async with lock:
                active += 1
                peak = max(peak, active)
            await asyncio.sleep(0.01)
            async with lock:
                active -= 1
            return 1

        async def _fail() -> None:
            raise RuntimeError("upstream")

        await asyncio.gather(*(limiter.run(operation) for _ in range(8)))
        assert peak <= 2
        limiter.limit = 2
        with pytest.raises(RuntimeError):
            await limiter.run(_fail)
        assert limiter.limit == 1

    @pytest.mark.asyncio
    async def test_full_admission_queue_is_rejected(self) -> None:
        limiter = AdaptiveLimiter(initial=1, maximum=1, queue_limit=0)
        started = asyncio.Event()
        release = asyncio.Event()

        async def blocking() -> None:
            started.set()
            await release.wait()

        holder = asyncio.create_task(limiter.run(blocking))
        await started.wait()
        try:
            with pytest.raises(AdmissionRejected):
                await limiter.run(blocking)
        finally:
            release.set()
            await holder


# ===========================================================================
# 2. Goal Budgeting, Depth Boundaries, and Loop Detection
# ===========================================================================

class TestBudgetAndLoopDetection:
    """Tests for goal budget limits, depth enforcement, and loop stopping."""

    def test_budget_enforces_calls_and_depth(self) -> None:
        manager = BudgetManager()
        manager.create("goal", GoalBudget(max_calls=1, max_depth=0, max_cost=2))
        manager.reserve("goal", "call-1", depth=0, cost=1)
        with pytest.raises(BudgetDenied, match="max_calls"):
            manager.reserve("goal", "call-2", depth=0, cost=1)

    def test_budget_enforces_depth_and_ttl(self) -> None:
        manager = BudgetManager()
        manager.create("deep", GoalBudget(max_depth=1))
        with pytest.raises(BudgetDenied, match="max_depth"):
            manager.reserve("deep", "call", depth=2, cost=1)

        manager.create("short", GoalBudget(ttl_s=0.001))
        time.sleep(0.01)
        with pytest.raises(BudgetDenied, match="ttl"):
            manager.reserve("short", "call", depth=0, cost=1)

    def test_repeated_identical_calls_are_stopped_as_a_loop(self) -> None:
        manager = BudgetManager()
        manager.create("loop", GoalBudget(max_calls=500, max_depth=2, max_cost=1000))
        for index in range(100):
            manager.reserve("loop", f"call-{index}", depth=0, cost=1, fingerprint="same")
        with pytest.raises(LoopDetected):
            manager.reserve("loop", "call-101", depth=0, cost=1, fingerprint="same")


# ===========================================================================
# 3. Singleflight Deduplication & Caching
# ===========================================================================

class TestDedupSingleflight:
    """Tests for in-flight request coalescing and short-TTL read caching."""

    @pytest.mark.asyncio
    async def test_identical_inflight_calls_share_one_operation(self) -> None:
        dedup = Singleflight()
        count = 0

        async def operation() -> str:
            nonlocal count
            count += 1
            await asyncio.sleep(0.01)
            return "result"

        results = await asyncio.gather(*(dedup.run("same", operation, cache_read=False) for _ in range(8)))
        assert [result for result, _ in results] == ["result"] * 8
        assert count == 1
        assert sum(shared for _, shared in results) == 7

    @pytest.mark.asyncio
    async def test_reads_are_cached_until_ttl(self) -> None:
        dedup = Singleflight(cache_ttl_s=1)
        count = 0

        async def operation() -> int:
            nonlocal count
            count += 1
            return count

        first, shared_first = await dedup.run("read", operation, cache_read=True)
        second, shared_second = await dedup.run("read", operation, cache_read=True)
        assert (first, second) == (1, 1)
        assert not shared_first and shared_second


# ===========================================================================
# 4. Coordination: Monotonic Fencing Tokens, CAS & Multi-Replica Safety
# ===========================================================================

class TestCoordinationAndCAS:
    """Tests for distributed leases, fencing tokens, and CAS state consistency."""

    @pytest.mark.asyncio
    async def test_leased_locks_expire_and_reject_concurrent_grants(self) -> None:
        locks = LockManager()
        first = await locks.acquire("resource", "goal-1", "agent-1", ttl_ms=10)
        assert first is not None
        second = await locks.acquire("resource", "goal-2", "agent-2", ttl_ms=10)
        assert second is None
        await asyncio.sleep(0.02)
        third = await locks.acquire("resource", "goal-2", "agent-2", ttl_ms=10)
        assert third is not None
        assert third.token > first.token

    @pytest.mark.asyncio
    async def test_fencing_token_monotonically_increases_on_reacquire(self) -> None:
        locks = LockManager()
        first = await locks.acquire("resource", "goal-1", "agent-1", ttl_ms=1)
        assert first is not None
        await asyncio.sleep(0.005)
        second = await locks.acquire("resource", "goal-1", "agent-1", ttl_ms=1)
        assert second is not None
        assert second.token == first.token + 1

    @pytest.mark.asyncio
    async def test_versioned_state_rejects_stale_writes(self) -> None:
        state = StateStore()
        first = await state.put("goal", "account", {"balance": 100}, expected_version=0)
        assert first.version == 1
        with pytest.raises(Exception):
            await state.put("goal", "account", {"balance": 200}, expected_version=0)
        second = await state.put("goal", "account", {"balance": 200}, expected_version=1)
        assert second.version == 2

    @pytest.mark.asyncio
    async def test_two_replica_monotonic_fencing_tokens(self) -> None:
        shared_backend: dict = {"leases": {}, "tokens": {}, "state": {}}
        replica_a = InMemoryStore(shared_data=shared_backend)
        replica_b = InMemoryStore(shared_data=shared_backend)

        lease_1 = await replica_a.acquire_lock("database", "goal-1", "agent-1", ttl_ms=50)
        assert lease_1 is not None
        assert lease_1.token == 1

        lease_b_fail = await replica_b.acquire_lock("database", "goal-2", "agent-2", ttl_ms=50)
        assert lease_b_fail is None

        released = await replica_a.release_lock("database", lease_1.token)
        assert released is True

        lease_2 = await replica_b.acquire_lock("database", "goal-2", "agent-2", ttl_ms=50)
        assert lease_2 is not None
        assert lease_2.token == 2

        await asyncio.sleep(0.06)
        lease_3 = await replica_a.acquire_lock("database", "goal-1", "agent-1", ttl_ms=50)
        assert lease_3 is not None
        assert lease_3.token == 3

    @pytest.mark.asyncio
    async def test_two_replica_cas_no_lost_updates(self) -> None:
        shared_backend: dict = {"leases": {}, "tokens": {}, "state": {}}
        replica_a = InMemoryStore(shared_data=shared_backend)
        replica_b = InMemoryStore(shared_data=shared_backend)

        v1 = await replica_a.put_state("goal-finance", "balance", 1000, expected_version=0)
        assert v1.version == 1

        async def update_a():
            return await replica_a.put_state("goal-finance", "balance", 1100, expected_version=1)

        async def update_b():
            return await replica_b.put_state("goal-finance", "balance", 1200, expected_version=1)

        results = await asyncio.gather(update_a(), update_b(), return_exceptions=True)
        successes = [r for r in results if not isinstance(r, Exception)]
        conflicts = [r for r in results if isinstance(r, StateConflict)]

        assert len(successes) == 1
        assert len(conflicts) == 1


# ===========================================================================
# 5. YAML Policy Engine, Quotas, Approvals & Hash Binding
# ===========================================================================

class TestPolicyAndApprovals:
    """Tests for policy rule evaluation, quotas, and cryptographic approval verification."""

    def _policy(self) -> PolicyEngine:
        return PolicyEngine.from_dict(
            {
                "default": "allow",
                "write_tools": ["write", "guarded_write", "delete", "refund"],
                "rules": [
                    {
                        "name": "read-only",
                        "agents": ["reader-*"],
                        "tools": ["write", "delete", "refund"],
                        "decision": "deny",
                        "reason": "read_only_agent",
                    },
                    {
                        "name": "refund-approval",
                        "agents": ["support-*"],
                        "tools": ["refund"],
                        "decision": "require_approval",
                        "reason": "high_value_refund",
                        "when": {"field": "amount", "gte": 100},
                    },
                ],
                "write_quotas": {"writer-*": 1},
            }
        )

    @pytest.mark.asyncio
    async def test_read_only_agent_is_denied(self) -> None:
        policy = self._policy()
        decision = await policy.evaluate(
            CallRequest(goal_id="goal", agent_id="reader-1", tool="delete", payload={"record": "secret"})
        )
        assert not decision.allowed
        assert decision.reason == "read_only_agent"

    @pytest.mark.asyncio
    async def test_high_value_refund_waits_for_approval_then_runs_once(self) -> None:
        policy = self._policy()
        first = await policy.evaluate(
            CallRequest(goal_id="goal", agent_id="support-1", tool="refund", payload={"amount": 250})
        )
        assert first.pending
        assert first.approval_id is not None

        policy.approvals.approve(first.approval_id)
        second = await policy.evaluate(
            CallRequest(
                goal_id="goal",
                agent_id="support-1",
                tool="refund",
                payload={"amount": 250},
                approval_id=first.approval_id,
            )
        )
        assert second.allowed

        # Replay attempt fails
        replay = await policy.evaluate(
            CallRequest(
                goal_id="goal",
                agent_id="support-1",
                tool="refund",
                payload={"amount": 250},
                approval_id=first.approval_id,
            )
        )
        assert not replay.allowed
        assert replay.reason == "approval_invalid"

    @pytest.mark.asyncio
    async def test_write_quota_stops_agent_from_mutating_again(self) -> None:
        policy = self._policy()
        first = await policy.evaluate(
            CallRequest(goal_id="goal", agent_id="writer-1", tool="write", payload={"record": "item-1"})
        )
        assert first.allowed
        second = await policy.evaluate(
            CallRequest(goal_id="goal", agent_id="writer-1", tool="write", payload={"record": "item-2"})
        )
        assert not second.allowed
        assert second.reason == "write_quota_exceeded"

    @pytest.mark.asyncio
    async def test_require_approval_flow_via_api(self) -> None:
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        async def refund_handler(request):
            return JSONResponse({"status": "refunded"})

        backend = Starlette(routes=[Route("/tools/refund", refund_handler, methods=["POST"])])
        transport = ASGITransport(app=backend)
        upstream = AsyncClient(transport=transport, base_url="http://backend")
        gateway = create_gateway(upstream_client=upstream)
        client = AsyncClient(transport=ASGITransport(app=gateway), base_url="http://gateway")
        try:
            await client.post("/v1/goals", json={"goal_id": "goal-appr", "max_calls": 10})
            payload = {"goal_id": "goal-appr", "agent_id": "support-1", "tool": "refund", "payload": {"amount": 500}}
            call1 = await client.post("/v1/call", json=payload)
            body1 = call1.json()
            assert body1["status"] == "pending_approval"
            approval_id = body1["approval_id"]

            appr_res = await client.post(f"/v1/approvals/{approval_id}/approve")
            assert appr_res.status_code == 200

            call2 = await client.post("/v1/call", json={**payload, "approval_id": approval_id})
            assert call2.json()["status"] == "ok"
        finally:
            await client.aclose()
            await upstream.aclose()


# ===========================================================================
# 6. Weighted Fair Queue Scheduler
# ===========================================================================

class TestWeightedFairScheduler:
    """Tests for weighted deficit round-robin and fairness across goals."""

    async def _run_ratio(self, scenario: dict[str, tuple[int, int]]) -> list[str]:
        limiter = AdaptiveLimiter(initial=1, maximum=1, queue_limit=100)
        scheduler = FairScheduler(limiter)
        grants: list[str] = []

        async def call(goal_id: str, weight: int) -> None:
            async with scheduler.slot(goal_id, weight):
                grants.append(goal_id)

        tasks = [
            asyncio.create_task(call(goal_id, weight))
            for goal_id, (weight, count) in scenario.items()
            for _ in range(count)
        ]
        await asyncio.gather(*tasks)
        return grants

    @pytest.mark.asyncio
    async def test_weighted_goal_gets_proportional_dispatches(self) -> None:
        grants = await self._run_ratio({"a": (1, 6), "b": (3, 18)})
        assert len(grants) == 24
        a_turns = sum(1 for g in grants if g == "a")
        b_turns = len(grants) - a_turns
        assert a_turns * 3 == b_turns

    @pytest.mark.asyncio
    async def test_two_equal_goals_interleave_turns(self) -> None:
        grants = await self._run_ratio({"g1": (1, 4), "g2": (1, 4)})
        assert len(grants) == 8
        assert grants.count("g1") == 4
        assert grants.count("g2") == 4

    @pytest.mark.asyncio
    async def test_per_goal_queue_cap_raises_but_other_goals_admit(self) -> None:
        limiter = AdaptiveLimiter(initial=1, maximum=1, queue_limit=100)
        scheduler = FairScheduler(limiter, max_queue=100, per_goal_limit=2)
        blocker = asyncio.Event()

        async def hold(goal_id: str) -> None:
            async with scheduler.slot(goal_id, 1):
                await blocker.wait()

        tasks = [asyncio.create_task(hold("a")) for _ in range(3)]
        await asyncio.sleep(0.01)
        assert len(scheduler.history) == 1  # one granted, two queued per-goal
        entry = scheduler.slot("a", 1)
        with pytest.raises(QueueOverflow) as caught:
            await entry.__aenter__()
        assert caught.value.scope.startswith("per_goal:a")
        blocker.set()
        await asyncio.gather(*tasks)

    @pytest.mark.asyncio
    async def test_global_queue_cap_raises_for_every_goal(self) -> None:
        limiter = AdaptiveLimiter(initial=1, maximum=1, queue_limit=100)
        scheduler = FairScheduler(limiter, max_queue=2, per_goal_limit=100)
        blocker = asyncio.Event()

        async def hold(goal_id: str) -> None:
            async with scheduler.slot(goal_id, 1):
                await blocker.wait()

        task = asyncio.create_task(hold("a"))
        await asyncio.sleep(0.01)
        queued = [asyncio.create_task(hold(goal)) for goal in ("b", "c")]
        await asyncio.sleep(0.01)
        with pytest.raises(QueueOverflow) as caught:
            await scheduler.slot("d", 1).__aenter__()
        assert caught.value.scope == "global"
        blocker.set()
        await asyncio.gather(task, *queued)

    @pytest.mark.asyncio
    async def test_fair_queue_serves_light_goal_under_flood(self) -> None:
        backend = create_backend(capacity=4, delay_s=0.02)
        upstream = AsyncClient(transport=ASGITransport(app=backend), base_url="http://backend")
        gateway = create_gateway(upstream_client=upstream)
        client = AsyncClient(transport=ASGITransport(app=gateway), base_url="http://gateway")
        try:
            await client.post("/v1/goals", json={"goal_id": "flood", "max_calls": 50, "weight": 1})
            await client.post("/v1/goals", json={"goal_id": "light", "max_calls": 10, "weight": 1})

            flood_reqs = [
                client.post("/v1/call", json={"goal_id": "flood", "agent_id": f"fl-{i}", "tool": "read", "payload": {"id": i}})
                for i in range(20)
            ]
            await asyncio.sleep(0.01)
            light_reqs = [
                client.post("/v1/call", json={"goal_id": "light", "agent_id": f"lt-{i}", "tool": "read", "payload": {"id": i + 100}})
                for i in range(4)
            ]

            all_res = await asyncio.gather(*flood_reqs, *light_reqs)
            light_res = all_res[20:]
            assert all(r.json()["status"] == "ok" for r in light_res)
        finally:
            await client.aclose()
            await upstream.aclose()


# ===========================================================================
# 7. Trace Tree & Audit Logs
# ===========================================================================

class TestTracesAndAudit:
    """Tests for causal trace hierarchy and parent-child tracking."""

    @pytest.mark.asyncio
    async def test_trace_tree_captures_parent_and_children(self) -> None:
        backend = create_backend(capacity=4, delay_s=0.005)
        upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=backend), base_url="http://backend")
        gateway = create_gateway(upstream_client=upstream)
        client_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway), base_url="http://gateway")
        sdk = GatewayClient(client=client_http)
        try:
            goal_id = "tree-goal-1"
            await sdk.create_goal(goal_id, max_calls=20, max_depth=5)

            # Root call (depth 0)
            root = await sdk.call(goal_id, "agent-root", "read", {"record": "root"})
            assert root.status == "ok"
            root_id = root.call_id
            assert root_id is not None

            # Child 1 (depth 1)
            child1 = await sdk.call(goal_id, "agent-c1", "read", {"record": "child1"}, parent_call_id=root_id)
            assert child1.status == "ok"
            c1_id = child1.call_id

            # Child 2 (depth 1)
            child2 = await sdk.call(goal_id, "agent-c2", "read", {"record": "child2"}, parent_call_id=root_id)
            assert child2.status == "ok"

            # Retrieve tree
            tree = await sdk.get_traces(goal_id)
            assert tree.goal_id == goal_id
            assert tree.total_calls == 3
            assert len(tree.roots) == 1
            assert len(tree.roots[0].children) == 2
        finally:
            await sdk.aclose()
            await client_http.aclose()
            await upstream.aclose()


# ===========================================================================
# 8. Python SDK Client & @tool Invocations
# ===========================================================================

class TestSDKClient:
    """Tests for thin Python client and tool decorator wrapping."""

    @pytest.mark.asyncio
    async def test_sdk_create_goal_and_call(self) -> None:
        backend = create_backend(capacity=4, delay_s=0.005)
        upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=backend), base_url="http://backend")
        gateway = create_gateway(upstream_client=upstream)
        client_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway), base_url="http://gateway")
        sdk = GatewayClient(client=client_http)
        try:
            goal = await sdk.create_goal("sdk-goal-1", max_calls=10, max_depth=3)
            assert goal.goal_id == "sdk-goal-1"
            assert goal.budget.max_calls == 10

            resp = await sdk.call(
                goal_id="sdk-goal-1",
                agent_id="agent-001",
                tool="read",
                payload={"record": "hot"},
            )
            assert resp.status == "ok"
            assert resp.result["status"] == "ok"
        finally:
            await sdk.aclose()
            await client_http.aclose()
            await upstream.aclose()

    @pytest.mark.asyncio
    async def test_sdk_tool_decorator(self) -> None:
        backend = create_backend(capacity=4, delay_s=0.005)
        upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=backend), base_url="http://backend")
        gateway = create_gateway(upstream_client=upstream)
        client_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway), base_url="http://gateway")
        sdk = GatewayClient(client=client_http)
        try:
            await sdk.create_goal("sdk-goal-2", max_calls=10)

            @sdk.tool("read")
            async def read_record(record: str) -> dict:
                return {"local": record}

            res = await read_record("hot", goal_id="sdk-goal-2", agent_id="agent-decorator")
            assert res["status"] == "ok"
            assert res["record"] == "hot"

            local_res = await read_record("hot")
            assert local_res == {"local": "hot"}
        finally:
            await sdk.aclose()
            await client_http.aclose()
            await upstream.aclose()

    @pytest.mark.asyncio
    async def test_sdk_call_returns_budget_exceeded_status(self) -> None:
        backend = create_backend(capacity=4, delay_s=0.005)
        upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=backend), base_url="http://backend")
        gateway = create_gateway(upstream_client=upstream)
        client_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway), base_url="http://gateway")
        sdk = GatewayClient(client=client_http)
        try:
            await sdk.create_goal("sdk-goal-3", max_calls=1)
            resp1 = await sdk.call("sdk-goal-3", "agent-1", "read", {"record": "hot"})
            assert resp1.status == "ok"

            resp2 = await sdk.call("sdk-goal-3", "agent-1", "read", {"record": "hot"})
            assert resp2.status == "budget_exceeded"
            assert resp2.reason == "max_calls"
            assert resp2.call_id is None
        finally:
            await sdk.aclose()
            await client_http.aclose()
            await upstream.aclose()

    @pytest.mark.asyncio
    async def test_sdk_locks_and_state(self) -> None:
        backend = create_backend(capacity=4, delay_s=0.005)
        upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=backend), base_url="http://backend")
        gateway = create_gateway(upstream_client=upstream)
        client_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway), base_url="http://gateway")
        sdk = GatewayClient(client=client_http)
        try:
            granted, token = await sdk.acquire_lock("hot-res", "goal-lock", "agent-1", ttl_ms=2000)
            assert granted is True
            assert token == 1

            released = await sdk.release_lock("hot-res", token)
            assert released is True

            val, version = await sdk.get_state("goal-state", "counter")
            assert val is None
            assert version == 0

            ok, v1 = await sdk.put_state("goal-state", "counter", 42, expected_version=0)
            assert ok is True
            assert v1 == 1
        finally:
            await sdk.aclose()
            await client_http.aclose()
            await upstream.aclose()

    @pytest.mark.asyncio
    async def test_sdk_langgraph_tool(self) -> None:
        backend = create_backend(capacity=4, delay_s=0.005)
        upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=backend), base_url="http://backend")
        gateway = create_gateway(upstream_client=upstream)
        client_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway), base_url="http://gateway")
        sdk = GatewayClient(client=client_http)
        try:
            await sdk.create_goal("lg-goal", max_calls=5)
            tool_def = langgraph_tool(sdk, "read", "Reads a record from upstream")
            assert tool_def["name"] == "read"
            assert callable(tool_def["coroutine"])

            result = await tool_def["coroutine"]({"record": "hot"}, goal_id="lg-goal", agent_id="lg-agent")
            assert result["status"] == "ok"
            assert result["record"] == "hot"
        finally:
            await sdk.aclose()
            await client_http.aclose()
            await upstream.aclose()


# ===========================================================================
# 9. Public Gateway REST API Endpoints & Health/Readiness
# ===========================================================================

class TestGatewayAPIAndMetrics:
    """Tests for health/ready probes, metrics exposition, and error handling."""

    @pytest.mark.asyncio
    async def test_health_and_ready_probes(self) -> None:
        gateway = create_gateway(upstream_client=AsyncClient(base_url="http://unused"))
        client = AsyncClient(transport=ASGITransport(app=gateway), base_url="http://gateway")
        try:
            health = await client.get("/health")
            assert health.status_code == 200
            assert health.json()["status"] == "ok"
            assert "uptime_s" in health.json()

            ready = await client.get("/ready")
            assert ready.status_code == 200
            assert ready.json()["status"] == "ready"
            assert ready.json()["store_connected"] is True
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_prometheus_metrics_endpoint(self) -> None:
        gateway = create_gateway(upstream_client=AsyncClient(base_url="http://unused"))
        client = AsyncClient(transport=ASGITransport(app=gateway), base_url="http://gateway")
        try:
            resp = await client.get("/metrics")
            assert resp.status_code == 200
            text = resp.text
            assert "agent_gateway_calls_total" in text
            assert "agent_gateway_concurrency_active" in text
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_state_route_returns_409_for_stale_version(self) -> None:
        gateway = create_gateway(upstream_client=AsyncClient(base_url="http://unused"))
        client = AsyncClient(transport=ASGITransport(app=gateway), base_url="http://gateway")
        try:
            first = await client.put("/v1/state/goal/key", headers={"If-Match": "0"}, json={"value": "one"})
            stale = await client.put("/v1/state/goal/key", headers={"If-Match": "0"}, json={"value": "two"})
            assert first.status_code == 200
            assert stale.status_code == 409
            assert stale.json()["reason"] == "version_mismatch"
        finally:
            await client.aclose()

    def test_config_env_overrides(self, monkeypatch) -> None:
        monkeypatch.setenv("AGENT_GATEWAY_ADMISSION_INITIAL", "10")
        monkeypatch.setenv("AGENT_GATEWAY_ADMISSION_MAX", "50")
        monkeypatch.setenv("AGENT_GATEWAY_ADMISSION_QUEUE_LIMIT", "500")
        cfg = GatewayConfig.from_env()
        assert cfg.admission_initial == 10
        assert cfg.admission_maximum == 50
        assert cfg.admission_queue_limit == 500


# ===========================================================================
# 10. Dynamic Upstream Targets & Reverse Proxy Routing
# ===========================================================================

class TestProxyModeAndDynamicTargets:
    """Tests for dynamic target registration and singleflight proxied routing."""

    def test_target_registration_via_api(self) -> None:
        app = create_gateway()
        client = TestClient(app)
        target = {
            "target_id": "service-a",
            "base_url": "http://127.0.0.1:9099",
            "allowed_methods": ["GET", "POST"],
            "timeout_seconds": 2.0,
        }
        res = client.post("/v1/targets", json=target)
        assert res.status_code == 200
        assert res.json()["status"] == "ok"
        assert res.json()["target"]["target_id"] == "service-a"

        list_res = client.get("/v1/targets")
        assert "service-a" in list_res.json()["targets"]

    @pytest.mark.asyncio
    async def test_proxy_dedup_and_forwarding(self) -> None:
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        import uvicorn

        call_count = 0

        async def handler(request):
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.04)
            return JSONResponse({"status": "ok", "call_count": call_count})

        mock_upstream = Starlette(routes=[Route("/api/test", handler, methods=["GET", "POST"])])
        config = uvicorn.Config(mock_upstream, host="127.0.0.1", port=9191, log_level="error")
        server = uvicorn.Server(config)
        server_task = asyncio.create_task(server.serve())
        await asyncio.sleep(0.2)

        try:
            app = create_gateway()
            client = AsyncClient(transport=ASGITransport(app=app), base_url="http://gateway")
            await client.post(
                "/v1/targets",
                json={"target_id": "mock-srv", "base_url": "http://127.0.0.1:9191", "allowed_methods": ["GET", "POST"]},
            )

            # Fire 3 concurrent GET calls -> should coalesce
            responses = await asyncio.gather(*(client.get("/v1/proxy/mock-srv/api/test") for _ in range(3)))
            assert all(r.status_code == 200 for r in responses)
            assert call_count == 1
        finally:
            server.should_exit = True
            await server_task
            await client.aclose()


# ===========================================================================
# 11. Demo Scene Workloads & Event Stream Verification
# ===========================================================================

class TestDemoScenesAndWorkloads:
    """Tests for simulated swarm recursive workloads and demo scene execution."""

    def test_workload_generation_and_determinism(self) -> None:
        assert build_workload(50, 7) == build_workload(50, 7)
        assert build_read_workload(50, 7) == build_read_workload(50, 7)
        assert build_read_workload(50, 7) != build_read_workload(50, 8)

    @pytest.mark.asyncio
    async def test_write_scene_prevents_lost_updates_with_fencing_tokens(self) -> None:
        harness = create_harness(delay_s=0.005)
        try:
            result = await run_scene("writes", seed=11, harness=harness)
            direct = result["direct"]
            gateway = result["gateway"]
            assert direct["lost_updates"] > 0
            assert gateway["lost_updates"] == 0
            assert gateway["final_value"] == 12
        finally:
            await harness.close()

    @pytest.mark.asyncio
    async def test_runaway_scene_hits_depth_or_budget_limit(self) -> None:
        harness = create_harness(delay_s=0.003)
        try:
            result = await run_scene("runaway", seed=5, harness=harness)
            gateway = result["gateway"]
            assert gateway["depth_reached"] >= 4
            assert gateway["budget_cancelled"] >= 1 or gateway["stop_reasons"]
            assert gateway["depth_limit"] == 3
        finally:
            await harness.close()
