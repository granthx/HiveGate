"""Goal-scoped call, depth, cost, and time-to-live enforcement."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field

from .models import GoalBudget


@dataclass
class GoalUsage:
    """Mutable usage tracked for one goal."""

    budget: GoalBudget
    created_at: float = field(default_factory=time.monotonic)
    calls: int = 0
    cost: float = 0.0
    call_depths: dict[str, int] = field(default_factory=dict)
    fingerprints: Counter[str] = field(default_factory=Counter)


class BudgetDenied(Exception):
    """Raised when a goal exceeds one configured limit."""

    def __init__(self, limit: str) -> None:
        self.limit = limit
        super().__init__(limit)


class LoopDetected(Exception):
    """Raised when a goal repeats the same call far too many times."""

    def __init__(self, count: int) -> None:
        self.count = count
        super().__init__("loop_detected")


class BudgetManager:
    """Creates goals and reserves usage before forwarding calls."""

    def __init__(self) -> None:
        self.goals: dict[str, GoalUsage] = {}

    def create(self, goal_id: str, budget: GoalBudget) -> GoalUsage:
        usage = GoalUsage(budget=budget)
        self.goals[goal_id] = usage
        return usage

    def get(self, goal_id: str) -> GoalUsage | None:
        return self.goals.get(goal_id)

    def reserve(
        self,
        goal_id: str,
        call_id: str,
        depth: int,
        cost: float,
        *,
        fingerprint: str | None = None,
        loop_limit: int = 100,
    ) -> None:
        """Reserve budget for one call, rejecting the call if a limit is hit."""

        usage = self.goals.get(goal_id)
        if usage is None:
            raise BudgetDenied("unknown_goal")
        if time.monotonic() - usage.created_at > usage.budget.ttl_s:
            raise BudgetDenied("ttl")
        if usage.calls >= usage.budget.max_calls:
            raise BudgetDenied("max_calls")
        if depth > usage.budget.max_depth:
            raise BudgetDenied("max_depth")
        if usage.cost + cost > usage.budget.max_cost:
            raise BudgetDenied("max_cost")
        if fingerprint is not None and usage.fingerprints[fingerprint] >= loop_limit:
            raise LoopDetected(usage.fingerprints[fingerprint])
        usage.calls += 1
        usage.cost += cost
        usage.call_depths[call_id] = depth
        if fingerprint is not None:
            usage.fingerprints[fingerprint] += 1
