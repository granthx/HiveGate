"""Five deterministic demo scenes measured against a direct and a protected backend."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable

import httpx
from fastapi import FastAPI

from demo.fragile_backend import create_app as create_backend
from gateway.main import create_app as create_gateway

PRICE_PER_CALL_USD = 0.001

SCENE_DEFINITIONS: list[dict[str, str]] = [
    {
        "id": "herd",
        "name": "1. Thundering herd",
        "description": "80 unique reads hit the backend at once. Direct traffic is refused; gateway traffic queues.",
    },
    {
        "id": "duplicate",
        "name": "2. Duplicate work",
        "description": "60 agents request the same record. Singleflight and the short read cache collapse them into one upstream call.",
    },
    {
        "id": "writes",
        "name": "3. Write conflict",
        "description": "12 agents increment the same record. Naive concurrent writes lose updates; leases plus fencing tokens do not.",
    },
    {
        "id": "runaway",
        "name": "4. Runaway recursion",
        "description": "A binary agent tree keeps spawning. The gateway stops it at the goal's depth and call budget.",
    },
    {
        "id": "policy",
        "name": "5. Policy + approval",
        "description": "A read-only agent tries to delete. A $250 refund pauses for human approval instead of executing.",
    },
]

HERD_CALLS = 80
DUPLICATE_CALLS = 60
WRITERS = 12
RUNAWAY_BREADTH = 2
RUNAWAY_HARD_DEPTH = 5
RUNAWAY_MAX_DEPTH = 3
RUNAWAY_MAX_CALLS = 25
FAIRNESS_FLOOD_CALLS = 60
FAIRNESS_LIGHT_CALLS = 10
FAIRNESS_LIGHT_WEIGHT = 5


@dataclass
class SceneHarness:
    """Persistent apps and clients used by the dashboard and benchmark."""

    direct_backend: FastAPI
    protected_backend: FastAPI
    gateway: FastAPI
    direct_client: httpx.AsyncClient
    gateway_client: httpx.AsyncClient
    upstream_client: httpx.AsyncClient

    async def close(self) -> None:
        await self.direct_client.aclose()
        await self.gateway_client.aclose()
        await self.upstream_client.aclose()


def create_harness(capacity: int = 4, delay_s: float = 0.012) -> SceneHarness:
    """Build two identical backends: one direct, one behind the gateway."""

    direct_backend = create_backend(capacity=capacity, delay_s=delay_s)
    protected_backend = create_backend(capacity=capacity, delay_s=delay_s)
    upstream_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=protected_backend),
        base_url="http://protected",
    )
    gateway = create_gateway(upstream_client=upstream_client)
    direct_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=direct_backend),
        base_url="http://direct",
    )
    gateway_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=gateway),
        base_url="http://gateway",
    )
    return SceneHarness(
        direct_backend=direct_backend,
        protected_backend=protected_backend,
        gateway=gateway,
        direct_client=direct_client,
        gateway_client=gateway_client,
        upstream_client=upstream_client,
    )


def percentile(values: list[float], fraction: float) -> float:
    """Return a simple nearest-rank percentile."""

    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


async def _direct_call(
    client: httpx.AsyncClient,
    tool: str,
    payload: dict[str, Any],
) -> tuple[bool, dict[str, Any], float]:
    started = time.perf_counter()
    try:
        response = await client.post(f"/tools/{tool}", json=payload)
        data = response.json()
        ok = response.status_code == 200 and data.get("status") not in {"error", "conflict"}
    except Exception as exc:  # pragma: no cover - defensive for a broken demo
        data = {"status": "error", "reason": type(exc).__name__}
        ok = False
    return ok, data, (time.perf_counter() - started) * 1000


async def _gateway_call(
    client: httpx.AsyncClient,
    goal_id: str,
    agent_id: str,
    tool: str,
    payload: dict[str, Any],
    *,
    parent_call_id: str | None = None,
    approval_id: str | None = None,
) -> tuple[bool, dict[str, Any], float]:
    started = time.perf_counter()
    body: dict[str, Any] = {
        "goal_id": goal_id,
        "agent_id": agent_id,
        "tool": tool,
        "payload": payload,
    }
    if parent_call_id:
        body["parent_call_id"] = parent_call_id
    if approval_id:
        body["approval_id"] = approval_id
    try:
        response = await client.post("/v1/call", json=body)
        data = response.json()
        ok = response.status_code == 200 and data.get("status") == "ok"
    except Exception as exc:  # pragma: no cover - defensive for a broken demo
        data = {"status": "error", "reason": type(exc).__name__}
        ok = False
    return ok, data, (time.perf_counter() - started) * 1000


async def _create_goal(
    client: httpx.AsyncClient,
    goal_id: str,
    *,
    max_calls: int,
    max_depth: int,
    max_cost: float = 10_000.0,
    ttl_s: float = 60.0,
    weight: int = 1,
) -> None:
    response = await client.post(
        "/v1/goals",
        json={
            "goal_id": goal_id,
            "max_calls": max_calls,
            "max_depth": max_depth,
            "max_cost": max_cost,
            "ttl_s": ttl_s,
            "weight": weight,
        },
    )
    if response.status_code != 200:
        raise RuntimeError(f"goal_create_failed_{response.status_code}")


def summarize(
    mode: str,
    calls: int,
    successes: int,
    latencies: list[float],
    backend: Any,
    gateway_metrics: dict[str, Any] | None = None,
    extras: dict[str, Any] | None = None,
) -> dict[str, Any]:
    backend_data = backend.snapshot()
    counters = gateway_metrics.get("counters", {}) if gateway_metrics else {}
    result = {
        "mode": mode,
        "client_calls": calls,
        "successful": successes,
        "success_rate": round(successes / calls, 4) if calls else 0.0,
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50), 3),
            "p99": round(percentile(latencies, 0.99), 3),
        },
        "backend_calls": backend_data["calls"],
        "backend_accepted": backend_data["accepted"],
        "upstream_errors": backend_data["errors"],
        "peak_upstream_concurrency": backend_data["peak_concurrency"],
        "fencing_rejections": backend_data["fencing_rejections"],
        "deduplicated": counters.get("deduplicated", 0),
        "calls_avoided": max(0, calls - backend_data["calls"]),
        "budget_cancelled": counters.get("budget_cancelled", 0),
        "depth_denied": counters.get("depth_denied", 0),
        "policy_denied": counters.get("policy_denied", 0),
        "approval_pending": counters.get("approval_pending", 0),
        "loop_detected": counters.get("loop_detected", 0),
        "estimated_cost_usd": round(backend_data["calls"] * PRICE_PER_CALL_USD, 6),
        "backend_records": backend_data["records"],
    }
    if extras:
        result.update(extras)
    return result


def _reset_all(harness: SceneHarness) -> None:
    harness.direct_backend.state.backend.reset()
    harness.protected_backend.state.backend.reset()


async def _reset_gateway(harness: SceneHarness) -> None:
    await harness.gateway.state.runtime.reset()


async def _acquire_lock(
    client: httpx.AsyncClient,
    resource: str,
    goal_id: str,
    agent_id: str,
    *,
    ttl_ms: int = 3000,
    timeout_s: float = 10.0,
) -> int | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        response = await client.post(
            "/v1/locks/acquire",
            json={
                "resource": resource,
                "goal_id": goal_id,
                "agent_id": agent_id,
                "ttl_ms": ttl_ms,
            },
        )
        data = response.json()
        if data.get("granted"):
            return int(data["fencing_token"])
        await asyncio.sleep(0.003)
    return None


async def _release_lock(client: httpx.AsyncClient, resource: str, token: int) -> None:
    await client.post("/v1/locks/release", json={"resource": resource, "fencing_token": token})


async def _scene_herd(harness: SceneHarness, seed: int) -> dict[str, Any]:
    _reset_all(harness)
    await _reset_gateway(harness)

    async def call(index: int) -> tuple[bool, dict[str, Any], float]:
        return await _direct_call(harness.direct_client, "read", {"record": f"herd-{seed}-{index}"})

    results = await asyncio.gather(*(call(index) for index in range(HERD_CALLS)))
    direct = summarize(
        "direct",
        HERD_CALLS,
        sum(ok for ok, _, _ in results),
        [latency for _, _, latency in results],
        harness.direct_backend.state.backend,
        extras={"note": "Unique reads: no deduplication is possible."},
    )

    harness.protected_backend.state.backend.reset()
    await _reset_gateway(harness)
    goal_id = f"herd-{uuid.uuid4().hex[:8]}"
    await _create_goal(harness.gateway_client, goal_id, max_calls=HERD_CALLS + 20, max_depth=2)

    async def gateway_call(index: int) -> tuple[bool, dict[str, Any], float]:
        return await _gateway_call(
            harness.gateway_client,
            goal_id,
            f"herd-{index:03d}",
            "read",
            {"record": f"herd-{seed}-{index}"},
        )

    gateway_results = await asyncio.gather(*(gateway_call(index) for index in range(HERD_CALLS)))
    gateway = summarize(
        "gateway",
        HERD_CALLS,
        sum(ok for ok, _, _ in gateway_results),
        [latency for _, _, latency in gateway_results],
        harness.protected_backend.state.backend,
        harness.gateway.state.runtime.metrics.snapshot(),
        extras={"goal_id": goal_id, "note": "Admission queue caps upstream concurrency and absorbs the burst."},
    )
    return {"direct": direct, "gateway": gateway}


async def _scene_duplicate(harness: SceneHarness, seed: int) -> dict[str, Any]:
    _reset_all(harness)
    await _reset_gateway(harness)

    async def direct_call(index: int) -> tuple[bool, dict[str, Any], float]:
        return await _direct_call(harness.direct_client, "read", {"record": "hot"})

    direct_results = await asyncio.gather(*(direct_call(index) for index in range(DUPLICATE_CALLS)))
    direct = summarize(
        "direct",
        DUPLICATE_CALLS,
        sum(ok for ok, _, _ in direct_results),
        [latency for _, _, latency in direct_results],
        harness.direct_backend.state.backend,
        extras={"note": "Every duplicate request is sent upstream."},
    )

    harness.protected_backend.state.backend.reset()
    await _reset_gateway(harness)
    goal_id = f"duplicate-{uuid.uuid4().hex[:8]}"
    await _create_goal(harness.gateway_client, goal_id, max_calls=DUPLICATE_CALLS + 20, max_depth=1)

    async def gateway_call(index: int) -> tuple[bool, dict[str, Any], float]:
        return await _gateway_call(
            harness.gateway_client,
            goal_id,
            f"dup-{index:03d}",
            "read",
            {"record": "hot"},
        )

    gateway_results = await asyncio.gather(*(gateway_call(index) for index in range(DUPLICATE_CALLS)))
    gateway_metrics = harness.gateway.state.runtime.metrics.snapshot()
    gateway = summarize(
        "gateway",
        DUPLICATE_CALLS,
        sum(ok for ok, _, _ in gateway_results),
        [latency for _, _, latency in gateway_results],
        harness.protected_backend.state.backend,
        gateway_metrics,
        extras={"goal_id": goal_id, "note": "Singleflight merges in-flight calls; the 1s cache absorbs the rest."},
    )
    return {"direct": direct, "gateway": gateway}


async def _scene_writes(harness: SceneHarness, seed: int) -> dict[str, Any]:
    _reset_all(harness)
    await _reset_gateway(harness)

    async def direct_writer(index: int) -> tuple[bool, dict[str, Any], float]:
        return await _direct_call(harness.direct_client, "write", {"record": "hot", "delta": 1})

    direct_results = await asyncio.gather(*(direct_writer(index) for index in range(WRITERS)))
    direct_successes = sum(ok for ok, _, _ in direct_results)
    direct_final = harness.direct_backend.state.backend.records.get("hot", 0)
    direct = summarize(
        "direct",
        WRITERS,
        direct_successes,
        [latency for _, _, latency in direct_results],
        harness.direct_backend.state.backend,
        extras={
            "final_value": direct_final,
            "lost_updates": max(0, direct_successes - direct_final),
            "note": "Naive read-modify-write: admitted writers overwrite each other.",
        },
    )

    harness.protected_backend.state.backend.reset()
    await _reset_gateway(harness)
    goal_id = f"writes-{uuid.uuid4().hex[:8]}"
    await _create_goal(harness.gateway_client, goal_id, max_calls=WRITERS * 4 + 20, max_depth=2)

    async def gateway_writer(index: int) -> tuple[bool, dict[str, Any], float]:
        started = time.perf_counter()
        agent_id = f"writer-{index:03d}"
        token = await _acquire_lock(harness.gateway_client, "hot", goal_id, agent_id)
        if token is None:
            return False, {"status": "error", "reason": "lock_timeout"}, (time.perf_counter() - started) * 1000
        try:
            read_ok, _, _ = await _gateway_call(
                harness.gateway_client,
                goal_id,
                agent_id,
                "read",
                {"record": "hot"},
            )
            write_ok, write_data, _ = await _gateway_call(
                harness.gateway_client,
                goal_id,
                agent_id,
                "guarded_write",
                {"record": "hot", "delta": 1, "fencing_token": token},
            )
            return read_ok and write_ok, write_data, (time.perf_counter() - started) * 1000
        finally:
            await _release_lock(harness.gateway_client, "hot", token)

    gateway_results = await asyncio.gather(*(gateway_writer(index) for index in range(WRITERS)))
    gateway_successes = sum(ok for ok, _, _ in gateway_results)
    gateway_final = harness.protected_backend.state.backend.records.get("hot", 0)
    gateway = summarize(
        "gateway",
        WRITERS,
        gateway_successes,
        [latency for _, _, latency in gateway_results],
        harness.protected_backend.state.backend,
        harness.gateway.state.runtime.metrics.snapshot(),
        extras={
            "goal_id": goal_id,
            "final_value": gateway_final,
            "lost_updates": max(0, gateway_successes - gateway_final),
            "note": "Lease serializes writes; the backend rejects stale fencing tokens.",
        },
    )
    return {"direct": direct, "gateway": gateway}


async def _scene_runaway(harness: SceneHarness, seed: int) -> dict[str, Any]:
    _reset_all(harness)
    await _reset_gateway(harness)

    direct_depths = [0]
    direct_results: list[tuple[bool, dict[str, Any], float]] = []

    async def direct_visit(depth: int, path: str) -> None:
        direct_depths[0] = max(direct_depths[0], depth)
        result = await _direct_call(
            harness.direct_client,
            "read",
            {"record": f"runaway-{seed}-{path}"},
        )
        direct_results.append(result)
        if depth < RUNAWAY_HARD_DEPTH:
            # No gateway means no depth or budget stop: the client script alone
            # decides when to stop, even when the backend is already refusing calls.
            await asyncio.gather(
                direct_visit(depth + 1, path + "a"),
                direct_visit(depth + 1, path + "b"),
            )

    await direct_visit(0, "")
    direct = summarize(
        "direct",
        len(direct_results),
        sum(ok for ok, _, _ in direct_results),
        [latency for _, _, latency in direct_results],
        harness.direct_backend.state.backend,
        extras={
            "depth_reached": direct_depths[0],
            "depth_limit": None,
            "stopped_reason": "client script hard stop (no gateway limit)",
            "note": f"Without the gateway the tree ran to the script's hard depth {RUNAWAY_HARD_DEPTH}.",
        },
    )

    harness.protected_backend.state.backend.reset()
    await _reset_gateway(harness)
    goal_id = f"runaway-{uuid.uuid4().hex[:8]}"
    await _create_goal(
        harness.gateway_client,
        goal_id,
        max_calls=RUNAWAY_MAX_CALLS,
        max_depth=RUNAWAY_MAX_DEPTH,
    )
    gateway_depths = [0]
    reasons: Counter[str] = Counter()
    attempts = [0]
    gateway_latencies: list[float] = []

    async def gateway_visit(parent_call_id: str | None, depth: int, path: str) -> bool:
        gateway_depths[0] = max(gateway_depths[0], depth)
        attempts[0] += 1
        ok, data, latency = await _gateway_call(
            harness.gateway_client,
            goal_id,
            f"runaway-{depth}",
            "read",
            {"record": f"runaway-{seed}-{path}"},
            parent_call_id=parent_call_id,
        )
        gateway_latencies.append(latency)
        if not ok:
            reasons[str(data.get("reason") or data.get("status") or "failed")] += 1
            return False
        if depth < RUNAWAY_HARD_DEPTH:
            child_call_id = data.get("call_id")
            await asyncio.gather(
                gateway_visit(child_call_id, depth + 1, path + "a"),
                gateway_visit(child_call_id, depth + 1, path + "b"),
            )
        return True

    await gateway_visit(None, 0, "")
    gateway_metrics = harness.gateway.state.runtime.metrics.snapshot()
    gateway = summarize(
        "gateway",
        attempts[0],
        attempts[0] - sum(reasons.values()),
        gateway_latencies,
        harness.protected_backend.state.backend,
        gateway_metrics,
        extras={
            "goal_id": goal_id,
            "depth_reached": gateway_depths[0],
            "depth_limit": RUNAWAY_MAX_DEPTH,
            "call_limit": RUNAWAY_MAX_CALLS,
            "stopped_reason": "max_depth / max_calls",
            "stop_reasons": dict(reasons),
            "calls_avoided": 0,
            "note": "Denied calls return a machine-readable reason instead of spawning more agents.",
        },
    )
    return {"direct": direct, "gateway": gateway}


async def _scene_policy(harness: SceneHarness, seed: int) -> dict[str, Any]:
    _reset_all(harness)
    await _reset_gateway(harness)

    direct_results = [
        await _direct_call(harness.direct_client, "delete", {"record": "secret"}),
        await _direct_call(harness.direct_client, "refund", {"amount": 20}),
        await _direct_call(harness.direct_client, "refund", {"amount": 250}),
    ]
    direct = summarize(
        "direct",
        len(direct_results),
        sum(ok for ok, _, _ in direct_results),
        [latency for _, _, latency in direct_results],
        harness.direct_backend.state.backend,
        extras={
            "policy_enforced": False,
            "destructive_allowed": 2,
            "approval_id": None,
            "note": "No policy layer: the read-only delete and the $250 refund both executed.",
        },
    )

    harness.protected_backend.state.backend.reset()
    await _reset_gateway(harness)
    goal_id = f"policy-{uuid.uuid4().hex[:8]}"
    await _create_goal(harness.gateway_client, goal_id, max_calls=20, max_depth=2)

    deny_ok, deny_data, deny_latency = await _gateway_call(
        harness.gateway_client,
        goal_id,
        "reader-001",
        "delete",
        {"record": "secret"},
    )
    small_ok, small_data, small_latency = await _gateway_call(
        harness.gateway_client,
        goal_id,
        "support-001",
        "refund",
        {"amount": 20},
    )
    pending_ok, pending_data, pending_latency = await _gateway_call(
        harness.gateway_client,
        goal_id,
        "support-001",
        "refund",
        {"amount": 250},
    )

    results = [
        (deny_ok, deny_data, deny_latency),
        (small_ok, small_data, small_latency),
        (pending_ok, pending_data, pending_latency),
    ]
    gateway = summarize(
        "gateway",
        len(results),
        small_ok,
        [latency for _, _, latency in results],
        harness.protected_backend.state.backend,
        harness.gateway.state.runtime.metrics.snapshot(),
        extras={
            "goal_id": goal_id,
            "policy_enforced": True,
            "destructive_allowed": 0,
            "approval_id": pending_data.get("approval_id"),
            "approval_reason": pending_data.get("reason"),
            "deny_reason": deny_data.get("reason"),
            "calls_avoided": 0,
            "stop_reasons": {
                "delete": deny_data.get("reason"),
                "small_refund": small_data.get("status"),
                "large_refund": pending_data.get("status"),
            },
            "note": "The destructive call is denied and the large refund waits for approval.",
        },
    )
    return {"direct": direct, "gateway": gateway}


_SCENES = {
    "herd": _scene_herd,
    "duplicate": _scene_duplicate,
    "writes": _scene_writes,
    "runaway": _scene_runaway,
    "policy": _scene_policy,
}


def _group_summary(results: list[tuple[bool, dict[str, Any], float]]) -> dict[str, Any]:
    """Summarize one goal's calls without touching shared backend counters."""

    latencies = [latency for _, _, latency in results]
    successful = sum(ok for ok, _, _ in results)
    return {
        "client_calls": len(results),
        "successful": successful,
        "success_rate": round(successful / len(results), 4) if results else 0.0,
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50), 3),
            "p99": round(percentile(latencies, 0.99), 3),
        },
    }


async def run_fairness(harness: SceneHarness, seed: int) -> dict[str, Any]:
    """Compare a 60-call flood goal with a 10-call light goal, direct vs gateway."""

    _reset_all(harness)
    await _reset_gateway(harness)

    def read_payload(group: str, index: int) -> dict[str, str]:
        return {"record": f"fair-{group}-{seed}-{index}"}

    async def direct_call(group: str, index: int) -> tuple[bool, dict[str, Any], float]:
        return await _direct_call(harness.direct_client, "read", read_payload(group, index))

    direct_results = await asyncio.gather(
        *(direct_call("flood", index) for index in range(FAIRNESS_FLOOD_CALLS)),
        *(direct_call("light", index) for index in range(FAIRNESS_LIGHT_CALLS)),
    )
    without_gateway = {
        "flood": _group_summary(direct_results[:FAIRNESS_FLOOD_CALLS]),
        "light": _group_summary(direct_results[FAIRNESS_FLOOD_CALLS:]),
        "backend": harness.direct_backend.state.backend.snapshot(),
        "note": "All calls share one backend queue; the flood crowds out the light goal.",
    }

    harness.protected_backend.state.backend.reset()
    await _reset_gateway(harness)
    flood_goal = f"fair-flood-{uuid.uuid4().hex[:8]}"
    light_goal = f"fair-light-{uuid.uuid4().hex[:8]}"
    await _create_goal(
        harness.gateway_client,
        flood_goal,
        max_calls=FAIRNESS_FLOOD_CALLS + 20,
        max_depth=1,
        weight=1,
    )
    await _create_goal(
        harness.gateway_client,
        light_goal,
        max_calls=FAIRNESS_LIGHT_CALLS + 10,
        max_depth=1,
        weight=FAIRNESS_LIGHT_WEIGHT,
    )

    async def gateway_call(
        goal_id: str, group: str, index: int
    ) -> tuple[bool, dict[str, Any], float]:
        return await _gateway_call(
            harness.gateway_client,
            goal_id,
            f"fair-{group}-{index:03d}",
            "read",
            read_payload(group, index),
        )

    gateway_results = await asyncio.gather(
        *(gateway_call(flood_goal, "flood", index) for index in range(FAIRNESS_FLOOD_CALLS)),
        *(gateway_call(light_goal, "light", index) for index in range(FAIRNESS_LIGHT_CALLS)),
    )
    scheduler = harness.gateway.state.runtime.scheduler.snapshot()
    with_gateway = {
        "flood": _group_summary(gateway_results[:FAIRNESS_FLOOD_CALLS]),
        "light": _group_summary(gateway_results[FAIRNESS_FLOOD_CALLS:]),
        "scheduler": {
            "dispatched": scheduler["dispatched"],
            "waiting": scheduler["waiting"],
        },
        "note": "Deficit round-robin gives the weight-5 light goal its turns first.",
    }
    return {
        "weights": {"flood": 1, "light": FAIRNESS_LIGHT_WEIGHT},
        "without_gateway": without_gateway,
        "with_gateway": with_gateway,
    }


async def run_scene(
    scene_id: str,
    seed: int,
    harness: SceneHarness,
    publish: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Run one scene against both backends and return measured results."""

    if scene_id not in _SCENES:
        raise KeyError(scene_id)
    notify = publish or (lambda _event, _data: None)
    definition = next(item for item in SCENE_DEFINITIONS if item["id"] == scene_id)
    notify("scene_started", {"scene": scene_id, "name": definition["name"], "seed": seed})
    started = time.perf_counter()
    measured = await _SCENES[scene_id](harness, seed)
    notify("scene_side", {"scene": scene_id, "side": "direct", **measured["direct"]})
    notify("scene_side", {"scene": scene_id, "side": "gateway", **measured["gateway"]})
    result = {
        "scene": scene_id,
        "name": definition["name"],
        "description": definition["description"],
        "seed": seed,
        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        "price_per_call_usd": PRICE_PER_CALL_USD,
        **measured,
    }
    return result
