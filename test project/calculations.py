"""calculations.py — Centralised, LLM-free, deterministic math for Zifi Agent Gateway.

ALL numeric computation (scores, percentiles, ratios, rates) lives here.
No heuristics, no LLM, no random fabrication.  Every function is a pure
deterministic function of its inputs.

Dependencies: numpy (required), scipy.stats (optional — falls back to pure
numpy when scipy is absent so the module works in minimal installs too).

Usage::

    from calculations import (
        success_rate, compute_gateway_valid_pct, benchmark_overall_score,
        latency_degradation_ratio, percentile, four_pillar_score,
        latency_waterfall_summary, calls_avoided, dedup_ratio,
        cost_per_successful_task,
    )
"""

from __future__ import annotations

from typing import Sequence

import numpy as np

# ---------------------------------------------------------------------------
# Optional scipy import — degrade gracefully if not installed
# ---------------------------------------------------------------------------
try:
    from scipy import stats as _scipy_stats  # noqa: F401
    _HAS_SCIPY = True
except ImportError:
    _HAS_SCIPY = False


# ---------------------------------------------------------------------------
# Status weight map (single source of truth — AGENTS.md §7 Metrics)
# ---------------------------------------------------------------------------
STATUS_WEIGHTS: dict[str, int] = {
    "PROTECTED": 100,
    "PASS": 90,
    "DETECTED": 90,
    "INFERRED": 75,
    "NOT_DETECTED_STATICALLY": 70,
    "WARN": 62,
    "UNKNOWN": 50,
    "LACKING": 38,
}

# Evidence confidence weights (Unknown evidence lowers confidence)
EVIDENCE_CONFIDENCE_WEIGHTS: dict[str, float] = {
    "MEASURED": 1.0,
    "DETECTED": 0.85,
    "INFERRED": 0.60,
    "NOT_DETECTED_STATICALLY": 0.50,
    "WARN": 0.50,
    "LACKING": 0.35,
    "UNKNOWN": 0.0,
}

# Grade thresholds (matches build_four_pillar_evaluation logic)
GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (100, "A+ · GATEWAY PROTECTED"),
    (80,  "A · PRODUCTION READY"),
    (60,  "B · HARDENING RECOMMENDED"),
    (0,   "C · EXPOSED / LACKING CONTROLS"),
]

POSTURE_GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (85, "A · HARDENED POSTURE"),
    (70, "B · MODERATE CONTROLS"),
    (50, "C · ELEVATED RISK"),
    (0,  "D · EXPOSED / CRITICAL DEFICIT"),
]


# ---------------------------------------------------------------------------
# 1. Basic rate / ratio helpers
# ---------------------------------------------------------------------------

def success_rate(successful: int, total: int) -> float:
    """Return fraction of successful calls out of total (0.0–1.0).

    Returns 0.0 when *total* is 0 to avoid ZeroDivisionError.
    """
    total = int(total)
    successful = int(successful)
    if total <= 0:
        return 0.0
    return float(np.clip(successful / total, 0.0, 1.0))


def compute_gateway_valid_pct(
    client_calls: int,
    successful: int,
    depth_denied: int = 0,
    policy_denied: int = 0,
    approval_pending: int = 0,
    budget_cancelled: int = 0,
) -> float:
    """Return gateway-valid completion percentage (0–100).

    "Valid attempts" excludes calls that were *intentionally* stopped by
    policy so they do not count against the success rate.
    """
    total = int(client_calls)
    ok = int(successful)
    intentionally_stopped = int(depth_denied + policy_denied + approval_pending + budget_cancelled)
    valid_attempts = max(1, total - intentionally_stopped)
    pct = float(np.minimum(100.0, (ok / valid_attempts) * 100.0))
    return round(pct, 1)


def calls_avoided(client_calls: int, backend_calls: int) -> int:
    """Number of backend calls avoided by singleflight / dedup.

    Always non-negative — a negative value would indicate a bug upstream.
    """
    return max(0, int(client_calls) - int(backend_calls))


def dedup_ratio(deduplicated: int, client_calls: int) -> float:
    """Fraction of client calls coalesced by singleflight (0.0–1.0)."""
    client_calls = int(client_calls)
    if client_calls <= 0:
        return 0.0
    return float(np.clip(deduplicated / client_calls, 0.0, 1.0))


def cost_per_successful_task(total_cost_usd: float, successful_tasks: int) -> float:
    """Average cost in USD per successfully completed task.

    Returns *total_cost_usd* unchanged when *successful_tasks* == 0
    (worst-case — infinite cost — is represented as the total).
    """
    if int(successful_tasks) <= 0:
        return float(total_cost_usd)
    return round(float(total_cost_usd) / int(successful_tasks), 6)


# ---------------------------------------------------------------------------
# 2. Latency helpers
# ---------------------------------------------------------------------------

def latency_degradation_ratio(burst_p95_ms: float, warm_p50_ms: float) -> float:
    """Ratio of burst p95 to warm p50 latency (must be ≥ 1.0 for sensible input).

    A ratio ≥ 1.8 indicates Concurrent Burst Queueing Contention (§04_TELEMETRY).
    Clamps warm_p50_ms to 0.5 ms minimum to avoid division by near-zero.
    """
    warm = float(np.maximum(0.5, warm_p50_ms))
    burst = float(burst_p95_ms)
    return round(burst / warm, 2)


def percentile(values: Sequence[float], p: int) -> float:
    """Return the *p*-th percentile of *values* using numpy linear interpolation.

    *p* must be in [0, 100].  Returns 0.0 for empty sequences.
    """
    arr = np.asarray(values, dtype=float)
    if arr.size == 0:
        return 0.0
    p = int(np.clip(p, 0, 100))
    return float(np.percentile(arr, p))


def latency_waterfall_summary(
    cold_ms: float,
    ttfb_ms: float,
    download_ms: float,
    warm_p50_ms: float,
    burst_3x_p95_ms: float,
) -> dict[str, object]:
    """Compute a full latency waterfall summary dict.

    Returns a plain dict suitable for JSON serialisation with:
    - all five raw measurements (ms)
    - degradation_ratio (burst p95 / warm p50)
    - latency_cause (human-readable root-cause label)
    - slo_ok (bool — TTFB ≤ 250 ms and ratio ≤ 1.8)
    """
    cold_ms = float(cold_ms)
    ttfb_ms = float(ttfb_ms)
    download_ms = float(download_ms)
    warm_p50_ms = float(warm_p50_ms)
    burst_3x_p95_ms = float(burst_3x_p95_ms)

    ratio = latency_degradation_ratio(burst_3x_p95_ms, warm_p50_ms)

    if ratio >= 1.8:
        cause = f"Concurrent Burst Queueing Contention ({ratio}× p95 spike)"
    elif ttfb_ms > cold_ms * 0.72 and ttfb_ms > 180:
        cause = f"Upstream Server TTFB / Cold Handshake ({ttfb_ms}ms TTFB)"
    elif download_ms > ttfb_ms:
        cause = f"Payload Transfer / Uncompressed Bundle ({download_ms}ms transfer)"
    else:
        cause = f"Healthy Keep-Alive Response ({warm_p50_ms}ms warm p50)"

    slo_ok = bool(ttfb_ms <= 250 and ratio <= 1.8)

    return {
        "cold_total_ms": round(cold_ms, 1),
        "ttfb_ms": round(ttfb_ms, 1),
        "download_ms": round(download_ms, 1),
        "warm_p50_ms": round(warm_p50_ms, 1),
        "burst_3x_p95_ms": round(burst_3x_p95_ms, 1),
        "degradation_ratio": ratio,
        "latency_cause": cause,
        "slo_ok": slo_ok,
    }


# ---------------------------------------------------------------------------
# 3. Benchmark scoring
# ---------------------------------------------------------------------------

def benchmark_overall_score(statuses: Sequence[str]) -> int:
    """Compute the weighted average score (0–100) across benchmark row statuses.

    Uses STATUS_WEIGHTS as the single source of truth.  Unknown statuses get
    weight 50 (neutral) rather than crashing.
    """
    if not statuses:
        return 0
    weights = np.array([STATUS_WEIGHTS.get(s.upper(), 50) for s in statuses], dtype=float)
    return int(round(float(np.mean(weights))))


def four_pillar_score(benchmark_statuses: Sequence[str], has_gateway_run: bool = False) -> dict[str, object]:
    """Compute overall 4-Pillar score and letter grade purely from row statuses.

    Args:
        benchmark_statuses: list of status strings for each benchmark row.
        has_gateway_run:    retained for backward-compatible signature; score
                            is always computed from actual row statuses.

    Returns:
        {"score": int, "grade": str, "row_scores": list[int]}
    """
    statuses = list(benchmark_statuses)
    row_scores = [STATUS_WEIGHTS.get(s.upper(), 50) for s in statuses]

    score = benchmark_overall_score(statuses)
    grade = "C · EXPOSED / LACKING CONTROLS"
    for threshold, label in GRADE_THRESHOLDS:
        if score >= threshold:
            grade = label
            break

    return {
        "score": score,
        "grade": grade,
        "row_scores": row_scores,
    }


def compute_evidence_confidence(evidence_kinds: Sequence[str]) -> float:
    """Compute confidence percentage (0.0–100.0) from labelled evidence kinds.

    Evaluation requirement:
    - Pure function of labelled evidence.
    - Unknown evidence lowers confidence, it does not raise the score.
    """
    if not evidence_kinds:
        return 0.0
    weights = [EVIDENCE_CONFIDENCE_WEIGHTS.get(k.upper(), 0.0) for k in evidence_kinds]
    return round(float(np.mean(weights)) * 100.0, 1)


def evaluate_site_posture(
    benchmark_statuses: Sequence[str],
    evidence_kinds: Sequence[str] | None = None,
) -> dict[str, object]:
    """Compute site posture score, grade, and confidence independently from gateway effects.

    Evaluation requirement:
    - Separate 'site posture' (headers, rate-limit hints) from 'gateway effect'.
    - Never mix them in one score.
    """
    statuses = list(benchmark_statuses)
    # Posture treats PROTECTED status as PASS for passive posture scoring
    posture_statuses = ["PASS" if s.upper() == "PROTECTED" else s for s in statuses]
    score = benchmark_overall_score(posture_statuses)

    grade = "D · EXPOSED / CRITICAL DEFICIT"
    for threshold, label in POSTURE_GRADE_THRESHOLDS:
        if score >= threshold:
            grade = label
            break

    conf = compute_evidence_confidence(evidence_kinds or []) if evidence_kinds else 100.0

    return {
        "score": score,
        "grade": grade,
        "confidence": conf,
    }


def evaluate_gateway_effect(
    has_gateway_run: bool,
    benchmark_statuses: Sequence[str] | None = None,
    direct_metrics: dict[str, object] | None = None,
    gateway_metrics: dict[str, object] | None = None,
) -> dict[str, object]:
    """Compute gateway effect scorecard independently from passive site posture.

    Evaluation requirement:
    - If unmeasured: returns measured=False, score=None, grade="NOT MEASURED".
    - If measured: reports real runtime score, grade, and delta metrics.
    """
    if not has_gateway_run:
        return {
            "measured": False,
            "score": None,
            "grade": "NOT MEASURED",
            "confidence": 0.0,
            "delta_summary": "Reconnaissance only — Gateway not in path (no load/probe test executed)",
        }

    statuses = list(benchmark_statuses or [])
    score = benchmark_overall_score(statuses)
    grade = "C · EXPOSED / LACKING CONTROLS"
    for threshold, label in GRADE_THRESHOLDS:
        if score >= threshold:
            grade = label
            break

    d = direct_metrics or {}
    g = gateway_metrics or {}
    errors_avoided = max(0, int(d.get("upstream_errors") or 0) - int(g.get("upstream_errors") or 0))
    lost_prevented = max(0, int(d.get("lost_updates") or 0) - int(g.get("lost_updates") or 0))
    avoided_calls = int(g.get("calls_avoided") or 0)

    summary_parts: list[str] = [f"Gateway run measured with score {score}/100 ({grade})."]
    if errors_avoided > 0:
        summary_parts.append(f"Eliminated {errors_avoided} upstream 429 errors.")
    if lost_prevented > 0:
        summary_parts.append(f"Eliminated {lost_prevented} lost updates via fencing/CAS.")
    if avoided_calls > 0:
        summary_parts.append(f"Saved {avoided_calls} backend calls via singleflight dedup.")

    return {
        "measured": True,
        "score": score,
        "grade": grade,
        "confidence": 100.0,
        "errors_avoided": errors_avoided,
        "lost_updates_prevented": lost_prevented,
        "calls_avoided": avoided_calls,
        "delta_summary": " ".join(summary_parts),
    }


# ---------------------------------------------------------------------------
# 4. Format helpers (kept server-side so the LLM never touches display math)
# ---------------------------------------------------------------------------

def format_pct(rate_or_pct: float) -> str:
    """Format a rate (0–1) or percentage (0–100) as a display string like '33.3%'.

    Values ≤ 1.0 are assumed to be rates and multiplied by 100.
    """
    num = float(rate_or_pct)
    pct = num * 100.0 if num <= 1.0 else num
    return f"{pct:.1f}%"


def exposure_improvement_summary(
    exposed_success_rate: float,
    gateway_valid_pct: float,
    upstream_errors_exposed: int,
    upstream_errors_gateway: int,
    lost_updates_exposed: int,
    lost_updates_gateway: int,
) -> str:
    """Return a one-sentence human-readable improvement summary.

    This is the *only* place where display text is composed from numbers;
    no LLM is involved.
    """
    exposed_str = format_pct(exposed_success_rate)
    gateway_str = f"{gateway_valid_pct:.1f}%"
    errors_saved = int(upstream_errors_exposed) - int(upstream_errors_gateway)
    lost_saved = int(lost_updates_exposed) - int(lost_updates_gateway)
    parts: list[str] = [
        f"Agent Gateway raised valid completion from {exposed_str} to {gateway_str}"
    ]
    if errors_saved > 0:
        parts.append(f"with {upstream_errors_gateway} overload errors")
    if lost_saved > 0:
        parts.append(f"and {lost_updates_gateway} lost writes")
    return " ".join(parts) + "."

