"""YAML policy rules, human approvals, and per-agent write quotas."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import CallRequest

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "policies" / "default.yaml"
WRITE_TOOLS = {"write", "guarded_write", "delete", "refund"}


def _fingerprint(request: CallRequest) -> str:
    encoded = json.dumps(request.payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{request.goal_id}:{request.agent_id}:{request.tool}:{encoded}".encode()).hexdigest()


@dataclass
class PolicyDecision:
    """Result of evaluating one call against the policy rules."""

    allowed: bool
    reason: str | None = None
    rule: str | None = None
    approval_id: str | None = None
    pending: bool = False


@dataclass
class Approval:
    """A policy-required call waiting for a human decision."""

    approval_id: str
    goal_id: str
    agent_id: str
    tool: str
    payload: dict[str, Any]
    reason: str
    fingerprint: str
    status: str = "pending"
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 300.0)

    def public(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "goal_id": self.goal_id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "reason": self.reason,
            "status": self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "payload": self.payload,
        }


class ApprovalStore:
    """Process-local approval queue with payload binding and TTL expiration."""

    def __init__(self, ttl_seconds: float = 300.0) -> None:
        self._approvals: dict[str, Approval] = {}
        self.ttl_seconds = ttl_seconds

    def create(self, request: CallRequest, reason: str) -> Approval:
        now = time.time()
        approval = Approval(
            approval_id=uuid.uuid4().hex,
            goal_id=request.goal_id,
            agent_id=request.agent_id,
            tool=request.tool,
            payload=dict(request.payload),
            reason=reason,
            fingerprint=_fingerprint(request),
            created_at=now,
            expires_at=now + self.ttl_seconds,
        )
        self._approvals[approval.approval_id] = approval
        return approval

    def get(self, approval_id: str) -> Approval | None:
        approval = self._approvals.get(approval_id)
        if approval and approval.status == "pending" and approval.expires_at < time.time():
            approval.status = "expired"
        return approval

    def approve(self, approval_id: str) -> Approval | None:
        approval = self._approvals.get(approval_id)
        if approval is None:
            return None
        if approval.expires_at < time.time():
            approval.status = "expired"
            return None
        if approval.status != "pending":
            return None
        approval.status = "approved"
        return approval

    def consume(self, approval_id: str, request: CallRequest) -> bool:
        approval = self._approvals.get(approval_id)
        if approval is None:
            return False
        if approval.expires_at < time.time():
            approval.status = "expired"
            return False
        if approval.status != "approved":
            return False
        if approval.fingerprint != _fingerprint(request):
            return False
        approval.status = "used"
        return True

    def pending(self) -> list[Approval]:
        now = time.time()
        for a in self._approvals.values():
            if a.status == "pending" and a.expires_at < now:
                a.status = "expired"
        return [item for item in self._approvals.values() if item.status == "pending"]

    def reset(self) -> None:
        self._approvals.clear()


@dataclass
class Rule:
    """One declarative policy rule."""

    name: str
    decision: str
    reason: str
    agents: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    condition_field: str | None = None
    condition_gte: float | None = None
    condition_eq: Any = None

    def matches(self, request: CallRequest) -> bool:
        if self.agents and not any(fnmatch.fnmatch(request.agent_id, pattern) for pattern in self.agents):
            return False
        if self.tools and request.tool not in self.tools:
            return False
        if self.condition_field is not None:
            value = request.payload.get(self.condition_field)
            if self.condition_gte is not None:
                try:
                    if float(value) < self.condition_gte:
                        return False
                except (TypeError, ValueError):
                    return False
            if self.condition_eq is not None and value != self.condition_eq:
                return False
        return True


class PolicyEngine:
    """Evaluate calls against ordered rules and manage approvals."""

    def __init__(
        self,
        rules: list[Rule] | None = None,
        *,
        write_tools: set[str] | None = None,
        write_quotas: dict[str, int] | None = None,
        default: str = "allow",
    ) -> None:
        self.rules = rules or []
        self.write_tools = write_tools or set(WRITE_TOOLS)
        self.write_quotas = write_quotas or {}
        self.default = default
        self.approvals = ApprovalStore()
        self._writes: Counter[str] = Counter()

    @classmethod
    def from_file(cls, path: str | Path | None = None) -> "PolicyEngine":
        """Load rules from YAML. A missing file means allow-all."""

        policy_path = Path(path) if path else DEFAULT_POLICY_PATH
        if not policy_path.exists():
            return cls()
        data = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyEngine":
        """Build an engine from an already-parsed policy document."""

        rules: list[Rule] = []
        for raw in data.get("rules", []):
            condition = raw.get("when") or {}
            rules.append(
                Rule(
                    name=str(raw.get("name", "unnamed")),
                    decision=str(raw.get("decision", "allow")),
                    reason=str(raw.get("reason", raw.get("decision", "policy_denied"))),
                    agents=tuple(raw.get("agents", [])),
                    tools=tuple(raw.get("tools", [])),
                    condition_field=condition.get("field"),
                    condition_gte=condition.get("gte"),
                    condition_eq=condition.get("eq"),
                )
            )
        return cls(
            rules,
            write_tools=set(data.get("write_tools", WRITE_TOOLS)),
            write_quotas={str(key): int(value) for key, value in (data.get("write_quotas") or {}).items()},
            default=str(data.get("default", "allow")),
        )

    def _quota_for(self, agent_id: str) -> int | None:
        for pattern, quota in self.write_quotas.items():
            if fnmatch.fnmatch(agent_id, pattern):
                return quota
        return None

    async def evaluate(self, request: CallRequest) -> PolicyDecision:
        """Return allow, deny, or pending-approval for one call."""

        is_write = request.tool in self.write_tools
        if is_write:
            quota = self._quota_for(request.agent_id)
            if quota is not None and self._writes[request.agent_id] >= quota:
                return PolicyDecision(
                    allowed=False,
                    reason="write_quota_exceeded",
                    rule="write_quota",
                )

        matched_rule: Rule | None = None
        for rule in self.rules:
            if rule.matches(request):
                matched_rule = rule
                break

        if matched_rule is not None:
            if matched_rule.decision == "deny":
                return PolicyDecision(
                    allowed=False,
                    reason=matched_rule.reason,
                    rule=matched_rule.name,
                )
            if matched_rule.decision == "require_approval":
                if request.approval_id:
                    if self.approvals.consume(request.approval_id, request):
                        if is_write:
                            self._writes[request.agent_id] += 1
                        return PolicyDecision(allowed=True, rule=matched_rule.name)
                    return PolicyDecision(
                        allowed=False,
                        reason="approval_invalid",
                        rule=matched_rule.name,
                    )
                approval = self.approvals.create(request, matched_rule.reason)
                return PolicyDecision(
                    allowed=False,
                    pending=True,
                    reason=matched_rule.reason,
                    rule=matched_rule.name,
                    approval_id=approval.approval_id,
                )

        if is_write:
            self._writes[request.agent_id] += 1

        if self.default == "deny" and matched_rule is None:
            return PolicyDecision(allowed=False, reason="default_deny", rule="default")
        return PolicyDecision(allowed=True, rule=matched_rule.name if matched_rule else None)

    def reset(self) -> None:
        """Clear approvals and quota counters between demo scenes."""

        self.approvals.reset()
        self._writes.clear()
