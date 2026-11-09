"""Pydantic request and response models for the gateway HTTP API."""

from __future__ import annotations

import ipaddress
import time
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator


class GoalBudget(BaseModel):
    """Limits attached to one agent goal."""

    max_calls: int = Field(default=100, ge=1)
    max_depth: int = Field(default=5, ge=0)
    max_cost: float = Field(default=100.0, ge=0)
    ttl_s: float = Field(default=60.0, gt=0)
    weight: int = Field(default=1, ge=1, le=100)


class GoalCreateRequest(GoalBudget):
    """Request to create a goal."""

    goal_id: str | None = None


class GoalResponse(BaseModel):
    """Created goal response."""

    status: str = "ok"
    goal_id: str
    budget: GoalBudget


class UpstreamTarget(BaseModel):
    """Dynamic upstream target configuration for proxy mode."""

    target_id: str
    base_url: str
    allowed_methods: list[str] = Field(default_factory=lambda: ["GET", "POST", "HEAD"])
    timeout_seconds: float = Field(default=3.0, gt=0, le=60.0)
    auth_header: str | None = None

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        raw = (v or "").strip()
        parsed = urlsplit(raw)
        scheme = (parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            raise ValueError(f"Scheme disallowed: '{scheme}' is not permitted (only http/https)")
        if parsed.username or parsed.password:
            raise ValueError("Credentials in URL are disallowed")
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise ValueError("Missing hostname in base_url")

        # Check cloud metadata and link-local in any encoding (octal before decimal isdigit)
        ip_candidates: list[str] = []
        try:
            if hostname.startswith("0") and len(hostname) > 1 and all(c in "01234567" for c in hostname):
                val = int(hostname, 8)
                if 0 <= val <= 0xFFFFFFFF:
                    ip_candidates.append(str(ipaddress.IPv4Address(val)))
            elif hostname.startswith(("0x", "0X")):
                val = int(hostname, 16)
                if 0 <= val <= 0xFFFFFFFF:
                    ip_candidates.append(str(ipaddress.IPv4Address(val)))
            elif hostname.isdigit():
                val = int(hostname)
                if 0 <= val <= 0xFFFFFFFF:
                    ip_candidates.append(str(ipaddress.IPv4Address(val)))
        except (ValueError, OverflowError):
            pass

        if not ip_candidates:
            try:
                ip_obj = ipaddress.ip_address(hostname)
                ip_candidates.append(str(ip_obj))
            except ValueError:
                pass

        for ip_str in ip_candidates:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
                ip_obj = ip_obj.ipv4_mapped
            if ip_obj.is_link_local or str(ip_obj) == "169.254.169.254":
                raise ValueError(f"SSRF blocked: cloud metadata/link-local '{ip_str}' is forbidden")

        return raw


class TargetRegisterResponse(BaseModel):
    """Response after registering a target upstream."""

    status: str = "ok"
    target: UpstreamTarget


class CallRequest(BaseModel):
    """Agent tool invocation sent to the gateway."""

    goal_id: str
    agent_id: str
    tool: str
    payload: dict[str, Any] = Field(default_factory=dict)
    parent_call_id: str | None = None
    idempotency_key: str | None = None
    approval_id: str | None = None
    priority: int = Field(default=0, ge=0, le=100)
    estimated_cost: float = Field(default=1.0, ge=0)


class CallResponse(BaseModel):
    """Structured result for an invocation."""

    status: str
    call_id: str | None = None
    result: Any = None
    reason: str | None = None
    limit: str | None = None
    retry_after_ms: int | None = None
    approval_id: str | None = None
    depth: int | None = None


class LockAcquireRequest(BaseModel):
    """Request to acquire a leased resource lock."""

    resource: str
    goal_id: str
    agent_id: str
    ttl_ms: int = Field(default=5000, gt=0)


class LockReleaseRequest(BaseModel):
    """Request to release a resource lock."""

    resource: str
    fencing_token: int


class StateWriteRequest(BaseModel):
    """Versioned state write payload."""

    value: Any


class ApprovalResponse(BaseModel):
    """A human-approval request exposed to the dashboard."""

    approval_id: str
    goal_id: str
    agent_id: str
    tool: str
    reason: str
    status: str
    created_at: float


class TraceNode(BaseModel):
    """A node in the goal's call execution tree."""

    call_id: str
    parent_call_id: str | None = None
    agent_id: str
    tool: str
    status: str
    depth: int = 0
    duration_ms: float = 0.0
    reason: str | None = None
    created_at: float = Field(default_factory=time.time)
    children: list[TraceNode] = Field(default_factory=list)


class GoalTracesResponse(BaseModel):
    """Hierarchical call tree traces for a goal."""

    status: str = "ok"
    goal_id: str
    total_calls: int = 0
    max_depth_reached: int = 0
    roots: list[TraceNode] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    """Common structured error body."""

    status: str
    reason: str
    retry_after_ms: int | None = None
