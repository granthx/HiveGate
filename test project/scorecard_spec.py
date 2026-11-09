"""scorecard_spec.py — Authoritative Specification and Threshold Registry for the 4-Pillar Scorecard.

Grounds each benchmark dimension in an exact standard (W3C, RFC, OWASP, NIST) or explicitly
marks it 'heuristic'. Defines exact input signals, rules, mathematical thresholds, and
gateway protection mechanisms.
"""

from __future__ import annotations

from typing import Any, NamedTuple


class BenchmarkRowSpec(NamedTuple):
    row_id: str
    pillar: str
    dimension: str
    input_signals: list[str]
    rule_description: str
    thresholds: dict[str, Any]
    threshold_source: str
    gateway_module: str


SCORECARD_SPECS: list[BenchmarkRowSpec] = [
    BenchmarkRowSpec(
        row_id="latency_burst_tail",
        pillar="Pillar 1 · App, Latency & Telemetry",
        dimension="Server TTFB & 3× Burst Tail Latency (p95)",
        input_signals=["ttfb_ms", "burst_3x_p95_ms", "warm_p50_ms", "degradation_ratio", "upstream_errors"],
        rule_description=(
            "Pass if TTFB <= 250.0ms and degradation_ratio <= 1.8; "
            "Warn if TTFB > 250ms or degradation_ratio > 1.8; "
            "Unknown if latency unmeasured; "
            "Protected if Gateway admission control eliminates upstream 429s (errors == 0)."
        ),
        thresholds={"max_ttfb_ms": 250.0, "max_degradation_ratio": 1.8, "gateway_errors": 0},
        threshold_source="04_TELEMETRY §3.1 & §7.1 (Web Latency SLO & Concurrent Burst Queueing Contention)",
        gateway_module="admission.py + dedup.py",
    ),
    BenchmarkRowSpec(
        row_id="opentelemetry_correlation",
        pillar="Pillar 1 · App, Latency & Telemetry",
        dimension="OpenTelemetry GenAI Trace & Request Correlation",
        input_signals=["has_traceparent", "has_request_id", "call_id", "parent_call_id", "goal_id"],
        rule_description=(
            "Pass if W3C traceparent or X-Request-ID detected in headers; "
            "Lacking if headers missing; "
            "Protected if 100% of Gateway requests carry call_id + parent_call_id + goal_id span tree."
        ),
        thresholds={"min_traced_calls_pct": 100.0},
        threshold_source="04_TELEMETRY §2.1 & §4.5 (W3C TraceContext Recommendation & gen_ai.* span correlation)",
        gateway_module="metrics.py + pipeline.py",
    ),
    BenchmarkRowSpec(
        row_id="idempotency_concurrency",
        pillar="Pillar 1 · App, Latency & Telemetry",
        dimension="Idempotency & Optimistic Concurrency (CAS / ETag)",
        input_signals=["has_etag", "has_idempotency", "lost_updates", "cas_version"],
        rule_description=(
            "Pass if ETag or Idempotency-Key present on mutative endpoints; "
            "Lacking if unversioned; "
            "Protected if CAS versioning & fencing tokens reduce lost writes to exactly 0."
        ),
        thresholds={"max_lost_updates_allowed": 0},
        threshold_source="02_MASTER_DEPLOYMENT_GUIDE §3.2 & §5.7 (RFC 7232 ETag / If-Match & Martin Kleppmann Fencing Tokens)",
        gateway_module="locks.py + state.py",
    ),
    BenchmarkRowSpec(
        row_id="lethal_trifecta_defense",
        pillar="Pillar 2 · AI & API Security (OWASP 2026)",
        dimension="The Lethal Trifecta Defense (Input × Tools × Exfil)",
        input_signals=["has_active_agents", "agents_detected", "tools_detected", "has_csp", "policy_denied", "approval_pending"],
        rule_description=(
            "Pass if CSP present or 0 declared agents with unmediated mutative tools; "
            "Lacking if agents have unmediated access to tools; "
            "Protected if YAML policy blocks unauthorized execution and pauses high-value refunds for approval."
        ),
        thresholds={"unauthorized_executions": 0, "approval_gate_enforced": True},
        threshold_source="03_AI_SECURITY_PLAYBOOK §0 & OWASP Top 10 for Agentic Applications 2026 (ASI01 / ASI02)",
        gateway_module="policy.py (YAML + Approval Gate)",
    ),
    BenchmarkRowSpec(
        row_id="unbounded_consumption_cascades",
        pillar="Pillar 2 · AI & API Security (OWASP 2026)",
        dimension="OWASP LLM06 Unbounded Consumption & ASI08 Cascading Failures",
        input_signals=["has_ratelimit", "has_retry_after", "depth_reached", "depth_limit", "depth_denied", "calls_avoided"],
        rule_description=(
            "Pass if RateLimit or Retry-After headers present; "
            "Lacking if headers absent; "
            "Protected if recursive fan-out capped at depth <= 3 and in-flight duplicates coalesced."
        ),
        thresholds={"max_depth": 3, "upstream_429s": 0},
        threshold_source="03_AI_SECURITY_PLAYBOOK §2 LLM06 & §3 ASI08 (OWASP LLM06 Denial of Wallet & ASI08 Cascading Failures)",
        gateway_module="budgets.py + scheduler.py",
    ),
    BenchmarkRowSpec(
        row_id="multi_stack_discovery",
        pillar="Pillar 3 · Multi-Stack, Agent & Tool Discovery",
        dimension="Multi-Stack UI & Backend Inspection (HTML / Java / JSS / SPA)",
        input_signals=["tech_stack", "agents_detected", "tools_detected", "status_code"],
        rule_description=(
            "Pass/Detected if multi-stack tools or OpenAPI/MCP manifests detected; "
            "Not Detected Statically if static HTML scan finds no tools; "
            "Unknown if origin unreachable (status_code == 0)."
        ),
        thresholds={"min_inspectable_status": 200},
        threshold_source="02_MASTER_DEPLOYMENT_GUIDE §2 & §8.4 MCP/A2A (Model Context Protocol & Multi-Stack Surface Inspection)",
        gateway_module="zifi_browser.py (Multi-Stack Recon)",
    ),
    BenchmarkRowSpec(
        row_id="repeat_trial_reliability",
        pillar="Pillar 4 · LLM & Agent Eval-Ops",
        dimension="Repeat-Trial Reliability (pass^k) & Outcome State Assertion",
        input_signals=["success_rate", "trials_k", "lost_updates", "cas_version"],
        rule_description=(
            "Pass if pass^k >= 0.99 across k trials; "
            "Not Detected Statically if 0 active agents detected; "
            "Protected if 100% valid completion across trials with zero lost updates."
        ),
        thresholds={"pass_k_threshold": 0.99, "max_lost_updates": 0},
        threshold_source="01_EVALUATIONS_AND_OPS §4.2 & §14 Glossary (pass^k All-Trials-Succeed Metric)",
        gateway_module="pipeline.py + benchmark.py",
    ),
]


def get_spec_by_row_id(row_id: str) -> BenchmarkRowSpec:
    """Lookup specification for a benchmark row by its identifier."""
    for spec in SCORECARD_SPECS:
        if spec.row_id == row_id:
            return spec
    raise KeyError(f"Unknown scorecard row_id: {row_id}")

