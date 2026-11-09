"""llm_variance_runner.py — 5-Trial Variance and Distribution Benchmark (Task B7).

Executes the exact same goal 5 times across LLM or scripted swarm runs and
reports variance, min, median, max for:
- Calls made
- API tokens and cost ($ USD)
- Duplicates avoided
- Denials and throttles

Saves reproducible results to results/llm_swarm_variance.json.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any

# Add repo root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from demo.fragile_backend import create_app as create_backend
from demo.llm_swarm import LLMRunResult, LLMSwarmRunner
from gateway.main import create_app as create_gateway
from sdk.client import GatewayClient
import httpx


def calculate_distribution(values: list[float | int]) -> dict[str, float]:
    """Calculate min, median, max, and sample variance."""
    if not values:
        return {"min": 0.0, "median": 0.0, "max": 0.0, "variance": 0.0}
    vals = [float(v) for v in values]
    return {
        "min": round(min(vals), 4),
        "median": round(statistics.median(vals), 4),
        "max": round(max(vals), 4),
        "variance": round(statistics.variance(vals) if len(vals) > 1 else 0.0, 4),
    }


async def run_5_trial_variance(
    prompt: str = "Triage flash-sale customer escalations and reconcile hot order inventory records.",
    mode: str = "auto",
    num_trials: int = 5,
    output_path: str = "results/llm_swarm_variance.json",
) -> dict[str, Any]:
    """Execute 5 identical trials and report distribution."""
    # Create in-process test infrastructure
    backend_app = create_backend(capacity=4, delay_s=0.002)
    backend_transport = httpx.ASGITransport(app=backend_app)
    upstream_client = httpx.AsyncClient(transport=backend_transport, base_url="http://backend")

    gateway_app = create_gateway(upstream_client=upstream_client)
    gateway_transport = httpx.ASGITransport(app=gateway_app)
    gateway_client = httpx.AsyncClient(transport=gateway_transport, base_url="http://gateway")
    sdk = GatewayClient(client=gateway_client)

    runner = LLMSwarmRunner(sdk)

    trial_results: list[LLMRunResult] = []
    print("================================================================================", flush=True)
    print("               AGENT GATEWAY — 5-TRIAL LLM SWARM VARIANCE RUNNER                ", flush=True)
    print("================================================================================", flush=True)
    print(f"Goal Prompt  : {prompt}", flush=True)
    print(f"Target Trials: {num_trials} repeated runs", flush=True)
    print(f"Mode Request : {mode}", flush=True)
    print("--------------------------------------------------------------------------------", flush=True)

    for i in range(1, num_trials + 1):
        goal_id = f"trial-goal-{i}"
        res = await runner.run_goal(goal_id=goal_id, prompt=prompt, mode=mode, seed=100 + i)
        trial_results.append(res)
        print(
            f"Trial #{i}: Mode={res.mode:<8} Status='{res.llm_status[:40]}' "
            f"Calls={res.calls_made} Avoided={res.calls_avoided} Denied={res.denials} "
            f"Tokens={res.tokens.get('total_tokens', 0)} Cost=${res.tokens.get('cost_usd', 0.0):.6f}",
            flush=True,
        )

    # Compute distributions
    calls_dist = calculate_distribution([r.calls_made for r in trial_results])
    avoided_dist = calculate_distribution([r.calls_avoided for r in trial_results])
    denials_dist = calculate_distribution([r.denials for r in trial_results])
    tokens_dist = calculate_distribution([r.tokens.get("total_tokens", 0) for r in trial_results])
    cost_dist = calculate_distribution([r.tokens.get("cost_usd", 0.0) for r in trial_results])

    first = trial_results[0]
    final_mode = first.mode
    llm_status_summary = first.llm_status

    print("--------------------------------------------------------------------------------", flush=True)
    print("VARIANCE & DISTRIBUTION SUMMARY (across 5 identical runs):", flush=True)
    print(f"Mode Label        : {final_mode.upper()} (Status: {llm_status_summary})", flush=True)
    print(f"Calls Made        : Min={calls_dist['min']} | Med={calls_dist['median']} | Max={calls_dist['max']} | Var={calls_dist['variance']}", flush=True)
    print(f"Duplicates Avoided: Min={avoided_dist['min']} | Med={avoided_dist['median']} | Max={avoided_dist['max']} | Var={avoided_dist['variance']}", flush=True)
    print(f"Denials / Gated   : Min={denials_dist['min']} | Med={denials_dist['median']} | Max={denials_dist['max']} | Var={denials_dist['variance']}", flush=True)
    print(f"API Tokens        : Min={tokens_dist['min']} | Med={tokens_dist['median']} | Max={tokens_dist['max']} | Var={tokens_dist['variance']}", flush=True)
    print(f"Cost ($ USD)      : Min=${cost_dist['min']:.6f} | Med=${cost_dist['median']:.6f} | Max=${cost_dist['max']:.6f}", flush=True)
    print("================================================================================", flush=True)

    summary_payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "goal_prompt": prompt,
        "mode": final_mode,
        "llm_status": llm_status_summary,
        "fallback_reason": first.fallback_reason,
        "num_trials": num_trials,
        "distributions": {
            "calls_made": calls_dist,
            "duplicates_avoided": avoided_dist,
            "denials": denials_dist,
            "tokens": tokens_dist,
            "cost_usd": cost_dist,
        },
        "trials": [r.model_dump() for r in trial_results],
    }

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(summary_payload, indent=2), encoding="utf-8")
    print(f"Saved reproducible variance report to {output_path}", flush=True)

    await sdk.aclose()
    await upstream_client.aclose()
    return summary_payload


def main() -> None:
    parser = argparse.ArgumentParser(description="5-Trial LLM Swarm Variance Runner")
    parser.add_argument("--prompt", type=str, default="Triage flash-sale customer escalations and reconcile hot order inventory records.")
    parser.add_argument("--mode", type=str, default="auto", choices=["auto", "llm", "scripted"])
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--output", type=str, default="results/llm_swarm_variance.json")
    args = parser.parse_args()

    asyncio.run(run_5_trial_variance(
        prompt=args.prompt,
        mode=args.mode,
        num_trials=args.trials,
        output_path=args.output,
    ))


if __name__ == "__main__":
    main()

