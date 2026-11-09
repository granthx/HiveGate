"""Timeout-aware upstream forwarding with retries and a simple circuit breaker."""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any

import httpx

from .models import UpstreamTarget


class CircuitOpen(Exception):
    """Raised when an upstream has crossed the failure threshold."""


class Forwarder:
    """Forwards calls to the fragile backend and avoids retrying unsafe writes."""

    def __init__(
        self,
        upstream_client: httpx.AsyncClient,
        *,
        retries: int = 2,
        timeout_s: float = 2.0,
        failure_threshold: int = 5,
        cooldown_s: float = 1.0,
        seed: int = 0,
        proxy_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.client = upstream_client
        self.proxy_client = proxy_client or httpx.AsyncClient(timeout=10.0)
        self._owns_proxy_client = proxy_client is None
        self.retries = retries
        self.timeout_s = timeout_s
        self.failure_threshold = failure_threshold
        self.cooldown_s = cooldown_s
        self.failures = 0
        self.opened_at: float | None = None
        self.random = random.Random(seed)

    async def aclose(self) -> None:
        """Close managed clients."""
        if self._owns_proxy_client:
            await self.proxy_client.aclose()

    def reset(self) -> None:
        """Clear breaker state and failure counters between demo runs."""

        self.failures = 0
        self.opened_at = None

    async def call(self, tool: str, payload: dict[str, Any], *, idempotent: bool) -> httpx.Response:
        if self.opened_at and time.monotonic() - self.opened_at < self.cooldown_s:
            raise CircuitOpen
        if self.opened_at:
            self.opened_at = None
            self.failures = 0
        attempts = self.retries + 1 if idempotent else 1
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                response = await self.client.post(
                    f"/tools/{tool}",
                    json=payload,
                    timeout=self.timeout_s,
                )
                if response.status_code >= 500 or response.status_code == 429:
                    raise httpx.HTTPStatusError("upstream failure", request=response.request, response=response)
                self.failures = 0
                return response
            except (httpx.HTTPError, asyncio.TimeoutError) as exc:
                last_error = exc
                self.failures += 1
                if self.failures >= self.failure_threshold:
                    self.opened_at = time.monotonic()
                if attempt + 1 < attempts:
                    delay = 0.01 * (2**attempt) + self.random.random() * 0.01
                    await asyncio.sleep(delay)
        assert last_error is not None
        raise last_error

    async def forward_request(
        self,
        target: UpstreamTarget,
        method: str,
        subpath: str,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        *,
        idempotent: bool = False,
    ) -> httpx.Response:
        """Forward an HTTP request to a dynamic upstream target."""
        clean_path = subpath.lstrip("/")
        base = target.base_url.rstrip("/")
        url = f"{base}/{clean_path}" if clean_path else base

        req_headers = dict(headers or {})
        # Strip hop-by-hop and host headers
        for h in ["host", "content-length", "connection", "transfer-encoding"]:
            req_headers.pop(h, None)
            req_headers.pop(h.title(), None)

        if target.auth_header:
            req_headers["Authorization"] = target.auth_header

        timeout = target.timeout_seconds or self.timeout_s
        attempts = self.retries + 1 if idempotent else 1
        last_error: Exception | None = None

        for attempt in range(attempts):
            try:
                response = await self.proxy_client.request(
                    method=method,
                    url=url,
                    content=content,
                    headers=req_headers,
                    params=params,
                    timeout=timeout,
                )
                return response
            except (httpx.HTTPError, asyncio.TimeoutError) as exc:
                last_error = exc
                if attempt + 1 < attempts:
                    delay = 0.01 * (2**attempt) + self.random.random() * 0.01
                    await asyncio.sleep(delay)
        assert last_error is not None
        raise last_error
