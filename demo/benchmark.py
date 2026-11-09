"""Reproducible before/after benchmark for the fragile backend and gateway."""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from demo.scenes import (
    PRICE_PER_CALL_USD,
    create_harness,
    run_fairness,
    run_scene,
    summarize,
)
from demo.swarm import build_read_workload


async def run_traffic(harness: Any, count: int, seed: int) -> dict[str, Any]:
    """Run the same duplicate-heavy read swarm directly and through the gateway."""

    direct_backend = harness.direct_backend.state.backend
    protected_backend = harness.protected_backend.state.backend
    runtime = harness.gateway.state.runtime
    calls = build_read_workload(count, seed)

    direct_backend.reset()
    protected_backend.reset()
    await runtime.reset()

    async def direct_invoke(call: Any) -> tuple[bool, float]:
        started = time.perf_counter()
        response = await harness.direct_client.post(
            "/tools/read",
            json=call.payload,
        )
        body = response.json()
        ok = response.status_code == 200 and body.get("status") == "ok"
        return ok, (time.perf_counter() - started) * 1000

    direct_results = await asyncio.gather(*(direct_invoke(call) for call in calls))
    without_gateway = summarize(
        "direct",
        count,
        sum(ok for ok, _ in direct_results),
        [latency for _, latency in direct_results],
        direct_backend,
        extras={"note": "Every duplicate request is sent to the backend."},
    )

    protected_backend.reset()
    await runtime.reset()
    goal_id = f"benchmark-{seed}"
    goal_response = await harness.gateway_client.post(
        "/v1/goals",
        json={
            "goal_id": goal_id,
            "max_calls": count + 25,
            "max_depth": 2,
            "max_cost": 10_000,
            "ttl_s": 60,
        },
    )
    if goal_response.status_code != 200:
        raise RuntimeError(f"goal_create_failed_{goal_response.status_code}")

    async def gateway_invoke(call: Any) -> tuple[bool, float]:
        started = time.perf_counter()
        response = await harness.gateway_client.post(
            "/v1/call",
            json={
                "goal_id": goal_id,
                "agent_id": call.agent_id,
                "tool": call.tool,
                "payload": call.payload,
            },
        )
        body = response.json()
        ok = response.status_code == 200 and body.get("status") == "ok"
        return ok, (time.perf_counter() - started) * 1000

    gateway_results = await asyncio.gather(*(gateway_invoke(call) for call in calls))
    with_gateway = summarize(
        "gateway",
        count,
        sum(ok for ok, _ in gateway_results),
        [latency for _, latency in gateway_results],
        protected_backend,
        runtime.metrics.snapshot(),
        extras={"note": "Singleflight and the short read cache absorb duplicate reads."},
    )
    return {"without_gateway": without_gateway, "with_gateway": with_gateway}


def _format(value: Any, key: str | None = None) -> str:
    if value is None:
        return "n/a"
    if key in {"success_rate"}:
        return f"{float(value):.1%}"
    if key in {"estimated_cost_usd"}:
        return f"${float(value):.4f}"
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def _lookup(data: dict[str, Any], dotted: str) -> Any:
    """Resolve ``latency_ms.p50`` style keys for the printed table."""

    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _table(title: str, without: dict[str, Any], with_gateway: dict[str, Any], rows: list[tuple[str, str]]) -> None:
    print(title)
    print(f"{'metric':<32}{'without':>14}{'with gateway':>18}")
    print("-" * 64)
    for label, key in rows:
        left_value = _lookup(without, key)
        right_value = _lookup(with_gateway, key)
        left = _format(left_value, key.split(".")[-1] if "." in key else key)
        right = _format(right_value, key.split(".")[-1] if "." in key else key)
        print(f"{label:<32}{left:>14}{right:>18}")
    print()


def print_table(result: dict[str, Any]) -> None:
    """Print the measured comparison without inventing or rounding away results."""

    traffic = result["traffic"]
    print(f"seed={result['seed']} calls={result['calls']} price=${result['price_per_call_usd']:.4f}/upstream call")
    print(f"swarm={result['swarm']} generated_at={result['generated_at']}")
    print()
    _table(
        "A. Duplicate-heavy traffic",
        traffic["without_gateway"],
        traffic["with_gateway"],
        [
            ("success rate", "success_rate"),
            ("p50 latency (ms)", "latency_ms.p50"),
            ("p99 latency (ms)", "latency_ms.p99"),
            ("peak upstream concurrency", "peak_upstream_concurrency"),
            ("upstream errors", "upstream_errors"),
            ("backend calls", "backend_calls"),
            ("calls avoided", "calls_avoided"),
            ("deduplicated calls", "deduplicated"),
            ("estimated cost (USD)", "estimated_cost_usd"),
        ],
    )
    writes = result["scenes"]["writes"]
    _table(
        "B. Write conflict (12 concurrent writers)",
        writes["direct"],
        writes["gateway"],
        [
            ("successful writers", "successful"),
            ("final record value", "final_value"),
            ("lost updates", "lost_updates"),
            ("stale fencing tokens", "fencing_rejections"),
            ("p99 latency (ms)", "latency_ms.p99"),
        ],
    )
    runaway = result["scenes"]["runaway"]
    _table(
        "C. Runaway recursion (client hard stop depth 5)",
        runaway["direct"],
        runaway["gateway"],
        [
            ("attempted calls", "client_calls"),
            ("successful calls", "successful"),
            ("depth reached", "depth_reached"),
            ("budget stops", "budget_cancelled"),
            ("depth stops", "depth_denied"),
            ("upstream errors", "upstream_errors"),
        ],
    )
    fairness = result["fairness"]
    weights = fairness["weights"]
    _table(
        f"D. Fair queue (flood weight {weights['flood']} vs light weight {weights['light']})",
        fairness["without_gateway"],
        fairness["with_gateway"],
        [
            ("light goal success rate", "light.success_rate"),
            ("light goal p50 (ms)", "light.latency_ms.p50"),
            ("light goal p99 (ms)", "light.latency_ms.p99"),
            ("flood goal success rate", "flood.success_rate"),
            ("flood goal p50 (ms)", "flood.latency_ms.p50"),
        ],
    )
    print("No values in this table are hard-coded. Latencies include queue time;")
    print("the benchmark runs in-process over ASGI so both sides share the same backend.")


async def benchmark(count: int, seed: int) -> dict[str, Any]:
    """Run the traffic comparison and the coordination scenes with one seed."""

    harness = create_harness()
    try:
        traffic = await run_traffic(harness, count, seed)
        fairness = await run_fairness(harness, seed)
        writes = await run_scene("writes", seed, harness)
        runaway = await run_scene("runaway", seed, harness)
    finally:
        await harness.close()
    return {
        "seed": seed,
        "calls": count,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "price_per_call_usd": PRICE_PER_CALL_USD,
        "swarm": "simulated",
        "traffic": traffic,
        "fairness": fairness,
        "scenes": {"writes": writes, "runaway": runaway},
    }


def main() -> None:
    """CLI entry point."""

    parser = argparse.ArgumentParser(description="Run the reproducible Agent Gateway benchmark.")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--trials", type=int, default=1, help="run k repeated trials and report min/med/max variance & pass^k (e.g. --trials 5)")
    parser.add_argument("--quick", action="store_true", help="run the short rehearsal workload")
    parser.add_argument("--calls", type=int, default=None)
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="defaults to results/benchmark.json (full) or results/benchmark-quick.json (--quick)",
    )
    args = parser.parse_args()
    count = args.calls or (40 if args.quick else 120)

    if args.trials > 1:
        from demo.repeated_runner import run_repeated_benchmark, print_repeated_table, DEFAULT_SEEDS
        seeds = DEFAULT_SEEDS[: args.trials]
        if len(seeds) < args.trials:
            seeds.extend(range(200, 200 + (args.trials - len(seeds))))
        output = args.output or Path("results/repeated_benchmark.json")
        result = asyncio.run(run_repeated_benchmark(seeds=seeds, calls=count))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print_repeated_table(result)
        print(f"saved={output}")
        return

    output = args.output or Path("results/benchmark-quick.json" if args.quick else "results/benchmark.json")
    result = asyncio.run(benchmark(count, args.seed))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print_table(result)
    print(f"saved={output}")


if __name__ == "__main__":
    main()
