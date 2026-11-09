"""config.py — Gateway Environment Configuration and Defaults (Task B6).

Configures:
- Admission limiter thresholds (initial, max, queue limits).
- Upstream network timeouts and retries.
- Failure policy modes (fail-closed vs fail-open).
- Observability and Prometheus metrics endpoints.
- Redis storage URLs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class GatewayConfig:
    """Runtime configuration loaded from environment variables."""

    # Admission control parameters
    admission_initial: int = 2
    admission_maximum: int = 3
    admission_queue_limit: int = 200

    # Upstream timeouts and retries
    upstream_timeout_s: float = 5.0
    upstream_retries: int = 2

    # Failure policy: 'fail-closed' (default, safe for financial/state mutations)
    # or 'fail-open' (allows safe read-only operations during store/policy degradation)
    failure_policy: str = "fail-closed"

    # Approvals TTL
    approval_ttl_seconds: float = 300.0  # 5 minutes

    # Redis backend
    redis_url: str | None = None

    # Observability
    json_logging: bool = False
    metrics_enabled: bool = True

    @classmethod
    def from_env(cls) -> GatewayConfig:
        return cls(
            admission_initial=int(os.getenv("AGENT_GATEWAY_ADMISSION_INITIAL", "2")),
            admission_maximum=int(os.getenv("AGENT_GATEWAY_ADMISSION_MAX", "3")),
            admission_queue_limit=int(os.getenv("AGENT_GATEWAY_ADMISSION_QUEUE_LIMIT", "200")),
            upstream_timeout_s=float(os.getenv("AGENT_GATEWAY_UPSTREAM_TIMEOUT_S", "5.0")),
            upstream_retries=int(os.getenv("AGENT_GATEWAY_UPSTREAM_RETRIES", "2")),
            failure_policy=os.getenv("AGENT_GATEWAY_FAILURE_POLICY", "fail-closed").lower(),
            approval_ttl_seconds=float(os.getenv("AGENT_GATEWAY_APPROVAL_TTL_S", "300.0")),
            redis_url=os.getenv("REDIS_URL"),
            json_logging=bool(os.getenv("AGENT_GATEWAY_JSON_LOGS", "0") in ("1", "true", "yes")),
            metrics_enabled=bool(os.getenv("AGENT_GATEWAY_METRICS_ENABLED", "1") in ("1", "true", "yes")),
        )
