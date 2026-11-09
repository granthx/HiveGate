"""In-memory trace recorder that constructs call-tree graphs per goal.

Bounded so a long-running demo cannot grow without limit: the oldest goal is
evicted past ``max_goals``, and calls beyond ``max_calls_per_goal`` are counted
as dropped instead of stored.
"""

from __future__ import annotations

import asyncio
import time
from collections import Counter
from typing import Any

from .models import GoalTracesResponse, TraceNode


class TraceStore:
    """Stores execution trace events and builds hierarchical call trees."""

    def __init__(self, *, max_goals: int = 200, max_calls_per_goal: int = 5000) -> None:
        self.max_goals = max_goals
        self.max_calls_per_goal = max_calls_per_goal
        # dicts keep insertion order, so the first key is the oldest goal.
        self._traces: dict[str, dict[str, dict[str, Any]]] = {}
        self.dropped: Counter[str] = Counter()
        self._lock = asyncio.Lock()

    async def record(
        self,
        goal_id: str,
        call_id: str,
        agent_id: str,
        tool: str,
        status: str,
        *,
        parent_call_id: str | None = None,
        depth: int = 0,
        duration_ms: float = 0.0,
        reason: str | None = None,
    ) -> None:
        async with self._lock:
            calls = self._traces.get(goal_id)
            if calls is None:
                while len(self._traces) >= self.max_goals:
                    oldest = next(iter(self._traces))
                    del self._traces[oldest]
                    self.dropped.pop(oldest, None)
                calls = self._traces[goal_id] = {}
            if len(calls) >= self.max_calls_per_goal:
                self.dropped[goal_id] += 1
                return
            calls[call_id] = {
                "call_id": call_id,
                "parent_call_id": parent_call_id,
                "agent_id": agent_id,
                "tool": tool,
                "status": status,
                "depth": depth,
                "duration_ms": duration_ms,
                "reason": reason,
                "created_at": time.time(),
            }

    async def get_tree(self, goal_id: str) -> GoalTracesResponse:
        async with self._lock:
            calls = dict(self._traces.get(goal_id, {}))

        if not calls:
            return GoalTracesResponse(goal_id=goal_id, total_calls=0, max_depth_reached=0, roots=[])

        nodes: dict[str, TraceNode] = {
            cid: TraceNode(**data, children=[]) for cid, data in calls.items()
        }

        roots: list[TraceNode] = []
        max_depth = 0

        for node in nodes.values():
            max_depth = max(max_depth, node.depth)
            if node.parent_call_id and node.parent_call_id in nodes:
                nodes[node.parent_call_id].children.append(node)
            else:
                roots.append(node)

        return GoalTracesResponse(
            goal_id=goal_id,
            total_calls=len(calls),
            max_depth_reached=max_depth,
            roots=roots,
        )

    async def goals(self) -> list[str]:
        async with self._lock:
            return list(self._traces.keys())

    async def reset(self) -> None:
        async with self._lock:
            self._traces.clear()
            self.dropped.clear()
