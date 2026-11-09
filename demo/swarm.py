"""Seeded async swarm workloads shared by the benchmark and demo scenes."""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from typing import Any, Awaitable, Callable


@dataclass(frozen=True)
class SwarmCall:
    """One deterministic simulated agent call."""

    agent_id: str
    tool: str
    payload: dict[str, Any]


def build_workload(count: int, seed: int) -> list[SwarmCall]:
    """Build a repeatable mix of duplicate reads and hot-record writes."""

    randomizer = random.Random(seed)
    calls: list[SwarmCall] = []
    for index in range(count):
        agent_id = f"agent-{index:03d}"
        if randomizer.random() < 0.8:
            record = f"record-{randomizer.randrange(4)}"
            calls.append(SwarmCall(agent_id, "read", {"record": record}))
        else:
            calls.append(SwarmCall(agent_id, "write", {"record": "hot", "delta": 1}))
    return calls


def build_read_workload(count: int, seed: int) -> list[SwarmCall]:
    """Build a duplicate-heavy read swarm for the before/after traffic test."""

    randomizer = random.Random(seed)
    return [
        SwarmCall(
            agent_id=f"agent-{index:03d}",
            tool="read",
            payload={"record": f"record-{randomizer.randrange(4)}"},
        )
        for index in range(count)
    ]


async def run_workload(
    calls: list[SwarmCall],
    invoke: Callable[[SwarmCall], Awaitable[tuple[int, dict[str, Any]]]],
) -> list[tuple[int, dict[str, Any]]]:
    """Run all simulated calls concurrently."""

    return await asyncio.gather(*(invoke(call) for call in calls))
