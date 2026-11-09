"""repeated_runner.py — Defensible pass^k Repeated-Trial Benchmark Runner (Task B5).

Runs the full Agent Gateway benchmark across k >= 5 distinct deterministic seeds to:
1. Measure true variance (min, median, max, standard deviation) for latencies and success rates.
2. Eliminate timing-nondeterminism claims by reporting distribution envelopes rather than single runs.
3. Compute pass^k (fraction of trials where ALL operations succeeded with 0 errors and 0 lost updates).

Per 01_EVALUATIONS_AND_OPS.md §4.2:
"Rule: for agents always report pass^k (all k attempts succeed), not just pass@k (any of k succeeds).
pass^k is what users experience."
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import numpy as np

# Add project root to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from demo.benchmark import run_traffic
from demo.scenes import PRICE_PER_CALL_USD, create_harness, run_fairness, run_scene


DEFAULT_SEEDS: list[int] = [7, 13, 42, 99, 101]


def compute_distribution_stats(values: Sequence[float]) -> dict[str, float]:
    """Compute min, median, max, mean, and sample standard deviation for a metric series."""
    arr = [float(v) for v in values if v is not None]
    if not arr:
        return {"min": 0.0, "median": 0.0, "max": 0.0, "mean": 0.0, "std_dev": 0.0}
    if len(arr) == 1:
        return {"min": arr[0], "median": arr[0], "max": arr[0], "mean": arr[0], "std_dev": 0.0}
    return {
        "min": round(float(np.min(arr)), 2),
        "median": round(float(np.median(arr)), 2),
        "max": round(float(np.max(arr)), 2),
        "mean": round(float(np.mean(arr)), 2),
        "std_dev": round(float(np.std(arr, ddof=1)), 2),
    }


async def run_single_trial(seed: int, calls: int) -> dict[str, Any]:
    """Execute one complete trial across all 4 benchmark scenes under a given seed."""
    harness = create_harness()
    try:
        traffic = await run_traffic(harness, calls, seed)
        fairness = await run_fairness(harness, seed)
        writes = await run_scene("writes", seed, harness)
        runaway = await run_scene("runaway", seed, harness)
    finally:
        await harness.close()

    # Determine trial pass status (SLO: success_rate >= 0.95, lost_updates == 0, upstream_errors == 0)
    direct_traffic = traffic["without_gateway"]
    direct_writes = writes["direct"]
    direct_passed = bool(
        direct_traffic.get("success_rate", 0) >= 0.95
        and direct_traffic.get("upstream_errors", 1) == 0
        and direct_writes.get("lost_updates", 1) == 0
    )

    gw_traffic = traffic["with_gateway"]
    gw_writes = writes["gateway"]
    gw_passed = bool(
        gw_traffic.get("success_rate", 0) >= 0.95
        and gw_traffic.get("upstream_errors", 1) == 0
        and gw_writes.get("lost_updates", 1) == 0
    )

    return {
        "seed": seed,
        "direct": {
            "traffic": direct_traffic,
            "writes": direct_writes,
            "runaway": runaway["direct"],
            "fairness": fairness["without_gateway"],
            "passed": direct_passed,
        },
        "gateway": {
            "traffic": gw_traffic,
            "writes": gw_writes,
            "runaway": runaway["gateway"],
            "fairness": fairness["with_gateway"],
            "passed": gw_passed,
        },
    }


async def run_repeated_benchmark(
    seeds: Sequence[int] = DEFAULT_SEEDS,
    calls: int = 40,
) -> dict[str, Any]:
    """Execute repeated trials across seeds and aggregate variance & pass^k statistics."""
    seed_list = list(seeds)
    k = len(seed_list)
    assert k >= 1, "Must run at least 1 trial"

    trials: list[dict[str, Any]] = []
    for s in seed_list:
        trial = await run_single_trial(s, calls)
        trials.append(trial)

    # Aggregate metric distributions
    d_sr = [t["direct"]["traffic"]["success_rate"] for t in trials]
    d_p50 = [t["direct"]["traffic"]["latency_ms"]["p50"] for t in trials]
    d_p99 = [t["direct"]["traffic"]["latency_ms"]["p99"] for t in trials]
    d_err = [t["direct"]["traffic"]["upstream_errors"] for t in trials]
    d_lost = [t["direct"]["writes"]["lost_updates"] for t in trials]

    g_sr = [t["gateway"]["traffic"]["success_rate"] for t in trials]
    g_p50 = [t["gateway"]["traffic"]["latency_ms"]["p50"] for t in trials]
    g_p99 = [t["gateway"]["traffic"]["latency_ms"]["p99"] for t in trials]
    g_err = [t["gateway"]["traffic"]["upstream_errors"] for t in trials]
    g_lost = [t["gateway"]["writes"]["lost_updates"] for t in trials]
    g_avoided = [t["gateway"]["traffic"]["calls_avoided"] for t in trials]
    g_dedup = [t["gateway"]["traffic"]["deduplicated"] for t in trials]

    # pass^k: True only if ALL k trials succeeded
    direct_passes = sum(1 for t in trials if t["direct"]["passed"])
    direct_pass_k = bool(direct_passes == k)
    direct_pass_k_rate = round(direct_passes / k, 4)

    gateway_passes = sum(1 for t in trials if t["gateway"]["passed"])
    gateway_pass_k = bool(gateway_passes == k)
    gateway_pass_k_rate = round(gateway_passes / k, 4)

    summary = {
        "trials_count_k": k,
        "seeds": seed_list,
        "calls_per_trial": calls,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "price_per_call_usd": PRICE_PER_CALL_USD,
        "pass_k_analysis": {
            "slo_criteria": "success_rate >= 0.95 AND upstream_errors == 0 AND lost_updates == 0",
            "direct": {
                "passed_trials": direct_passes,
                "total_trials": k,
                "pass_k_satisfied": direct_pass_k,
                "pass_rate": direct_pass_k_rate,
            },
            "gateway": {
                "passed_trials": gateway_passes,
                "total_trials": k,
                "pass_k_satisfied": gateway_pass_k,
                "pass_rate": gateway_pass_k_rate,
            },
        },
        "distributions": {
            "direct": {
                "success_rate": compute_distribution_stats(d_sr),
                "p50_ms": compute_distribution_stats(d_p50),
                "p99_ms": compute_distribution_stats(d_p99),
                "upstream_errors": compute_distribution_stats(d_err),
                "lost_updates": compute_distribution_stats(d_lost),
            },
            "gateway": {
                "success_rate": compute_distribution_stats(g_sr),
                "p50_ms": compute_distribution_stats(g_p50),
                "p99_ms": compute_distribution_stats(g_p99),
                "upstream_errors": compute_distribution_stats(g_err),
                "lost_updates": compute_distribution_stats(g_lost),
                "calls_avoided": compute_distribution_stats(g_avoided),
                "deduplicated": compute_distribution_stats(g_dedup),
            },
        },
        "raw_trials": trials,
    }
    return summary


def format_stat_envelope(stat: dict[str, float], is_pct: bool = False) -> str:
    """Format min / median / max as a compact string."""
    if is_pct:
        return f"{stat['min']*100:.1f}% / {stat['median']*100:.1f}% / {stat['max']*100:.1f}%"
    return f"{stat['min']:.1f} / {stat['median']:.1f} / {stat['max']:.1f}"


def print_repeated_table(summary: dict[str, Any]) -> None:
    """Print clean comparison table showing min / median / max distributions and pass^k."""
    k = summary["trials_count_k"]
    seeds = summary["seeds"]
    d_dist = summary["distributions"]["direct"]
    g_dist = summary["distributions"]["gateway"]
    pk = summary["pass_k_analysis"]

    print("=" * 80)
    print(f"Agent Gateway Repeated-Trial Reliability Benchmark (pass^{k})")
    print(f"Seeds: {seeds} · Calls/Trial: {summary['calls_per_trial']} · Measured over live ASGI")
    print("=" * 80)
    print(f"{'Metric':<30}{'Without Gateway (min/med/max)':>24}{'With Gateway (min/med/max)':>26}")
    print("-" * 80)
    print(f"{'Success Rate':<30}{format_stat_envelope(d_dist['success_rate'], is_pct=True):>24}{format_stat_envelope(g_dist['success_rate'], is_pct=True):>26}")
    print(f"{'p50 Latency (ms)':<30}{format_stat_envelope(d_dist['p50_ms']):>24}{format_stat_envelope(g_dist['p50_ms']):>26}")
    print(f"{'p99 Latency (ms)':<30}{format_stat_envelope(d_dist['p99_ms']):>24}{format_stat_envelope(g_dist['p99_ms']):>26}")
    print(f"{'Upstream Errors (429)':<30}{format_stat_envelope(d_dist['upstream_errors']):>24}{format_stat_envelope(g_dist['upstream_errors']):>26}")
    print(f"{'Lost Writes (Race)':<30}{format_stat_envelope(d_dist['lost_updates']):>24}{format_stat_envelope(g_dist['lost_updates']):>26}")
    print(f"{'Calls Avoided':<30}{'0.0 / 0.0 / 0.0':>24}{format_stat_envelope(g_dist['calls_avoided']):>26}")
    print("-" * 80)
    print(f"{'pass^k Metric (All k pass)':<30}{str(pk['direct']['pass_k_satisfied']) + ' (' + str(pk['direct']['passed_trials']) + '/' + str(k) + ')':>24}{str(pk['gateway']['pass_k_satisfied']) + ' (' + str(pk['gateway']['passed_trials']) + '/' + str(k) + ')':>26}")
    print("=" * 80)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run repeated Agent Gateway trials and report pass^k distribution.")
    parser.add_argument("--trials", type=int, default=5, help="Number of seeded trials (k >= 5)")
    parser.add_argument("--calls", type=int, default=40, help="Number of traffic calls per trial")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "results" / "repeated_benchmark.json")
    args = parser.parse_args()

    seeds = DEFAULT_SEEDS[: args.trials]
    if len(seeds) < args.trials:
        seeds.extend(range(200, 200 + (args.trials - len(seeds))))

    summary = asyncio.run(run_repeated_benchmark(seeds=seeds, calls=args.calls))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print_repeated_table(summary)
    print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()

