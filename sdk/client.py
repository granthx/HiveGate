"""Agent Gateway Python SDK: client and tool decorators."""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, TypeVar

import httpx

from gateway.models import CallResponse, GoalResponse, GoalTracesResponse

F = TypeVar("F", bound=Callable[..., Any])


class GatewayError(Exception):
    """Raised when the gateway rejects or fails a call."""

    def __init__(self, status: str, reason: str | None = None, response: CallResponse | None = None) -> None:
        self.status = status
        self.reason = reason
        self.response = response
        super().__init__(f"Gateway call failed ({status}): {reason}")


class GatewayClient:
    """Async client for interacting with Agent Gateway."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000", client: httpx.AsyncClient | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(base_url=self.base_url)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> "GatewayClient":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    async def create_goal(
        self,
        goal_id: str,
        *,
        max_calls: int = 100,
        max_depth: int = 5,
        max_cost: float = 100.0,
        ttl_s: float = 60.0,
        weight: int = 1,
    ) -> GoalResponse:
        """Create or register an execution budget for a goal."""
        res = await self._client.post(
            "/v1/goals",
            json={
                "goal_id": goal_id,
                "max_calls": max_calls,
                "max_depth": max_depth,
                "max_cost": max_cost,
                "ttl_s": ttl_s,
                "weight": weight,
            },
        )
        res.raise_for_status()
        return GoalResponse.model_validate(res.json())

    async def call(
        self,
        goal_id: str,
        agent_id: str,
        tool: str,
        payload: dict[str, Any],
        *,
        parent_call_id: str | None = None,
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        priority: int = 0,
        estimated_cost: float = 1.0,
    ) -> CallResponse:
        """Execute a tool invocation through the gateway pipeline."""
        res = await self._client.post(
            "/v1/call",
            json={
                "goal_id": goal_id,
                "agent_id": agent_id,
                "tool": tool,
                "payload": payload,
                "parent_call_id": parent_call_id,
                "idempotency_key": idempotency_key,
                "approval_id": approval_id,
                "priority": priority,
                "estimated_cost": estimated_cost,
            },
        )
        res.raise_for_status()
        return CallResponse.model_validate(res.json())

    async def acquire_lock(
        self, resource: str, goal_id: str, agent_id: str, ttl_ms: int = 5000
    ) -> tuple[bool, int | None]:
        """Acquire a leased resource lock. Returns (granted, fencing_token)."""
        res = await self._client.post(
            "/v1/locks/acquire",
            json={
                "resource": resource,
                "goal_id": goal_id,
                "agent_id": agent_id,
                "ttl_ms": ttl_ms,
            },
        )
        res.raise_for_status()
        data = res.json()
        if data.get("granted"):
            return True, int(data["fencing_token"])
        return False, None

    async def release_lock(self, resource: str, fencing_token: int) -> bool:
        """Release a held lock by resource and fencing token."""
        res = await self._client.post(
            "/v1/locks/release",
            json={"resource": resource, "fencing_token": fencing_token},
        )
        res.raise_for_status()
        return bool(res.json().get("released", False))

    async def get_state(self, goal_id: str, key: str) -> tuple[Any, int]:
        """Fetch versioned shared state. Returns (value, version)."""
        res = await self._client.get(f"/v1/state/{goal_id}/{key}")
        res.raise_for_status()
        data = res.json()
        return data.get("value"), int(data.get("version", 0))

    async def put_state(self, goal_id: str, key: str, value: Any, expected_version: int) -> tuple[bool, int]:
        """CAS update to shared state. Returns (success, new_or_current_version)."""
        res = await self._client.put(
            f"/v1/state/{goal_id}/{key}",
            headers={"If-Match": str(expected_version)},
            json={"value": value},
        )
        if res.status_code == 200:
            return True, int(res.json()["version"])
        if res.status_code == 409:
            return False, int(res.json().get("version", 0))
        res.raise_for_status()
        return False, 0

    async def list_traces(self) -> list[str]:
        """List all goals with recorded execution traces."""
        res = await self._client.get("/v1/traces")
        res.raise_for_status()
        return list(res.json())

    async def get_traces(self, goal_id: str) -> GoalTracesResponse:
        """Fetch hierarchical call-tree trace for a goal."""
        res = await self._client.get(f"/v1/traces/{goal_id}")
        res.raise_for_status()
        return GoalTracesResponse.model_validate(res.json())

    def tool(
        self,
        name: str | None = None,
        *,
        default_cost: float = 1.0,
    ) -> Callable[[F], F]:
        """Decorator to route tool function calls through the Agent Gateway.

        The function must be async. When called with ``goal_id`` and
        ``agent_id`` keyword arguments, its bound arguments become the payload
        and the gateway forwards the call upstream (the local body is not run).
        Without that context the local body runs as a plain function.
        """

        def decorator(func: F) -> F:
            tool_name = name or func.__name__

            if inspect.iscoroutinefunction(func):
                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    goal_id = kwargs.pop("goal_id", None)
                    agent_id = kwargs.pop("agent_id", None)
                    parent_call_id = kwargs.pop("parent_call_id", None)
                    idempotency_key = kwargs.pop("idempotency_key", None)
                    approval_id = kwargs.pop("approval_id", None)
                    estimated_cost = kwargs.pop("estimated_cost", default_cost)

                    if not goal_id or not agent_id:
                        # If called without gateway context, fall back to executing locally
                        return await func(*args, **kwargs)

                    sig = inspect.signature(func)
                    bound = sig.bind_partial(*args, **kwargs)
                    bound.apply_defaults()
                    payload = dict(bound.arguments)

                    resp = await self.call(
                        goal_id=goal_id,
                        agent_id=agent_id,
                        tool=tool_name,
                        payload=payload,
                        parent_call_id=parent_call_id,
                        idempotency_key=idempotency_key,
                        approval_id=approval_id,
                        estimated_cost=estimated_cost,
                    )
                    if resp.status != "ok":
                        raise GatewayError(resp.status, resp.reason, resp)
                    return resp.result

                return async_wrapper  # type: ignore

            # Routing through the gateway is async I/O, so a sync wrapper could
            # only work by blocking on an event loop. Reject it up front instead
            # of failing later at call time.
            raise TypeError(f"@tool requires an async function; {func.__name__!r} is synchronous")

        return decorator


def langgraph_tool(
    client: GatewayClient,
    tool_name: str,
    description: str,
    *,
    default_cost: float = 1.0,
) -> dict[str, Any]:
    """Helper creating a LangGraph / LangChain compatible tool specification."""

    async def _invoke(payload: dict[str, Any], goal_id: str, agent_id: str, **kwargs: Any) -> Any:
        kwargs.setdefault("estimated_cost", default_cost)
        resp = await client.call(
            goal_id=goal_id,
            agent_id=agent_id,
            tool=tool_name,
            payload=payload,
            **kwargs,
        )
        if resp.status != "ok":
            raise GatewayError(resp.status, resp.reason, resp)
        return resp.result

    return {
        "name": tool_name,
        "description": description,
        "coroutine": _invoke,
    }
