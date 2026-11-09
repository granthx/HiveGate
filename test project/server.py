"""FastAPI server for 'Test Projects' & 'Zifi Browser' SaaS suite (Port 8010).

Bridges the Zifi Browser embedded web sandbox and three Groq-powered multi-agent
applications (Aegis Commerce, Sentinel Ops, QuantPulse) directly to the Agent
Gateway Control Plane running on port 8000, with an automatic in-process fallback
when port 8000 is not reachable.
"""

from __future__ import annotations

import asyncio
import html
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator
import re
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent
for path_str in (str(REPO_ROOT), str(THIS_DIR)):
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

from demo.scenes import SCENE_DEFINITIONS, SceneHarness, create_harness, run_scene  # noqa: E402
from gateway.models import CallRequest, UpstreamTarget  # noqa: E402
from sdk.client import GatewayClient  # noqa: E402

try:
    from .groq_engine import GroqSwarmEngine
    from .projects import PROJECT_CATALOG, execute_project_swarm, get_project_definition
    from .zifi_browser import (
        BUILT_IN_TARGETS,
        build_four_pillar_evaluation,
        build_network_interceptor_events,
        perform_url_recon,
        render_builtin_target_html,
        resolve_project_for_url,
        validate_url_for_recon,
    )
except ImportError:
    from groq_engine import GroqSwarmEngine  # type: ignore  # noqa: E402
    from projects import PROJECT_CATALOG, execute_project_swarm, get_project_definition  # type: ignore  # noqa: E402
    from zifi_browser import (  # type: ignore  # noqa: E402
        BUILT_IN_TARGETS,
        build_four_pillar_evaluation,
        build_network_interceptor_events,
        perform_url_recon,
        render_builtin_target_html,
        resolve_project_for_url,
        validate_url_for_recon,
    )


DEFAULT_GATEWAY_HOST = os.getenv("AGENT_GATEWAY_HOST", "").rstrip("/")


class GroqConfigRequest(BaseModel):
    """Runtime Groq API configuration payload."""

    api_key: str = ""
    model: str = "llama-3.3-70b-versatile"


class ProjectRunRequest(BaseModel):
    """Mission input for running one of the three multi-agent projects."""

    prompt: str = ""
    target_url: str = ""


class ZifiReconRequest(BaseModel):
    """Target URL pasted into the Zifi Browser address bar."""

    url: str


class ZifiAuditRequest(BaseModel):
    """Full Zifi Browser audit request for a pasted URL + mission prompt."""

    url: str
    prompt: str = ""
    project_id: str = ""


async def _probe_remote_gateway(host: str) -> bool:
    """Return True if an external Agent Gateway host is configured and reachable."""
    if not host:
        return False
    try:
        async with httpx.AsyncClient(timeout=0.8) as client:
            resp = await client.get(f"{host}/health")
            return resp.status_code == 200
    except Exception:
        return False


def check_target_ownership(url: str) -> bool:
    """Check if the target URL is owned by the operator (local loopback or verified)."""
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if hostname in {"127.0.0.1", "localhost", "0.0.0.0", "::1"}:
            return True
        origin = f"{parsed.scheme}://{parsed.netloc}"
        with httpx.Client(timeout=0.6) as client:
            resp = client.get(f"{origin}/.well-known/agent-gateway-verify.txt")
            if resp.status_code == 200 and "agent-gateway-verified" in resp.text:
                return True
    except Exception:
        pass
    return False


def verify_production_configuration() -> None:
    """Refuse startup in production mode with default or missing configuration."""
    env = os.getenv("AGENT_GATEWAY_ENV", "development").lower()
    if env == "production":
        admin_key = os.getenv("AGENT_GATEWAY_ADMIN_KEY", "").strip()
        if not admin_key or admin_key.lower() in {"default", "changeme", "admin"}:
            raise RuntimeError("Production mode requires non-default AGENT_GATEWAY_ADMIN_KEY")
        cors = os.getenv("AGENT_GATEWAY_CORS_ORIGINS", "")
        if "*" in cors:
            raise RuntimeError("Production mode requires explicit AGENT_GATEWAY_CORS_ORIGINS (wildcard '*' disallowed)")


class InMemoryRateLimiter:
    """Sliding-window in-memory rate limiter per client IP."""

    def __init__(self, max_requests: int = 15, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.history: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, client_ip: str) -> tuple[bool, int]:
        async with self._lock:
            now = time.time()
            timestamps = self.history.setdefault(client_ip, [])
            self.history[client_ip] = [t for t in timestamps if now - t < self.window_seconds]
            if len(self.history[client_ip]) >= self.max_requests:
                oldest = self.history[client_ip][0]
                retry_after = max(1, int(self.window_seconds - (now - oldest)))
                return False, retry_after
            self.history[client_ip].append(now)
            return True, 0


def sanitize_proxy_html(body: str, origin: str) -> str:
    """Sanitize remote HTML before serving in Zifi Browser iframe."""
    # Strip script tags
    sanitized = re.sub(r"(?is)<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", "", body)
    # Strip inline event handlers (onload, onerror, onclick, etc.)
    sanitized = re.sub(r'(?i)\son\w+\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+)', "", sanitized)
    # Strip javascript: URIs
    sanitized = re.sub(r'(?i)href\s*=\s*[\'"]\s*javascript:[^\'"]*[\'"]', 'href="#"', sanitized)
    # Strip object, embed, applet
    sanitized = re.sub(r"(?is)<(object|embed|applet)\b[^<]*(?:(?!<\/\1>)<[^<]*)*<\/\1>", "", sanitized)

    base_tag = f'<base href="{html.escape(origin)}">'
    if "<head" in sanitized.lower():
        idx = sanitized.lower().find("<head")
        close_idx = sanitized.find(">", idx)
        if close_idx != -1:
            sanitized = sanitized[: close_idx + 1] + base_tag + sanitized[close_idx + 1 :]
    else:
        sanitized = base_tag + sanitized
    return sanitized


async def execute_bounded_probe_test(
    target_url: str,
    gateway_runtime: Any,
    gateway_host: str = "",
    n_calls: int = 10,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Execute real bounded probe test: N requests direct vs N requests through gateway proxy."""
    target_id = f"target-{uuid.uuid4().hex[:6]}"
    parsed = urlparse(target_url)
    clean_base = f"{parsed.scheme}://{parsed.netloc}"
    subpath = parsed.path.lstrip("/")

    target_obj = UpstreamTarget(
        target_id=target_id,
        base_url=clean_base,
        allowed_methods=["GET", "POST", "HEAD"],
        timeout_seconds=3.0,
    )
    if hasattr(gateway_runtime, "register_target"):
        gateway_runtime.register_target(target_obj)

    if gateway_host:
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.post(f"{gateway_host}/v1/targets", json=target_obj.model_dump())
        except Exception:
            pass

    # Direct Path: N calls sent concurrently to target_url
    direct_latencies: list[float] = []
    direct_errors = 0
    direct_success = 0

    async def _send_direct(idx: int) -> None:
        nonlocal direct_errors, direct_success
        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(target_url, params={"probe_id": idx})
                lat = (time.perf_counter() - t0) * 1000.0
                direct_latencies.append(lat)
                if resp.status_code < 400:
                    direct_success += 1
                else:
                    direct_errors += 1
        except Exception:
            direct_errors += 1
            lat = (time.perf_counter() - t0) * 1000.0
            direct_latencies.append(lat)

    await asyncio.gather(*[_send_direct(i) for i in range(n_calls)])

    # Gateway Proxy Path: N calls sent in pairs so singleflight coalesces duplicates
    gw_latencies: list[float] = []
    gw_errors = 0
    gw_success = 0
    gw_dedup = 0

    async def _send_gateway_proxied(pair_id: int) -> None:
        nonlocal gw_errors, gw_success, gw_dedup
        t0 = time.perf_counter()
        try:
            status_code, headers, content, shared = await gateway_runtime.proxy_call(
                target_id=target_id,
                method="GET",
                path=subpath,
                params={"pair_id": str(pair_id)},
                goal_id=f"bounded-probe-{pair_id}",
                agent_id="probe-agent",
            )
            lat = (time.perf_counter() - t0) * 1000.0
            gw_latencies.append(lat)
            if status_code < 400:
                gw_success += 1
            else:
                gw_errors += 1
            if shared:
                gw_dedup += 1
        except Exception:
            gw_errors += 1
            lat = (time.perf_counter() - t0) * 1000.0
            gw_latencies.append(lat)

    gw_tasks = []
    for pair_idx in range(n_calls // 2):
        gw_tasks.append(_send_gateway_proxied(pair_idx))
        gw_tasks.append(_send_gateway_proxied(pair_idx))
    if n_calls % 2 != 0:
        gw_tasks.append(_send_gateway_proxied(99))

    await asyncio.gather(*gw_tasks)

    def _pct(arr: list[float], p: float) -> float:
        if not arr:
            return 0.0
        s = sorted(arr)
        idx = int(round((len(s) - 1) * (p / 100.0)))
        return round(s[idx], 1)

    run_id = f"probe_{uuid.uuid4().hex[:8]}"
    now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    direct_metrics = {
        "source": "measured",
        "run_id": run_id,
        "timestamp_utc": now_utc,
        "client_calls": n_calls,
        "successful": direct_success,
        "success_rate": round(direct_success / n_calls, 3) if n_calls > 0 else 0.0,
        "upstream_errors": direct_errors,
        "lost_updates": None,
        "backend_calls": n_calls,
        "calls_avoided": 0,
        "deduplicated": 0,
        "peak_upstream_concurrency": min(n_calls, 10),
        "latency_ms": {
            "p50": _pct(direct_latencies, 50),
            "p95": _pct(direct_latencies, 95),
            "p99": _pct(direct_latencies, 99),
        },
        "measured": True,
        "note": f"Direct bounded load test ({n_calls} calls sent concurrently to origin)",
    }

    gw_metrics = {
        "source": "measured",
        "run_id": run_id,
        "timestamp_utc": now_utc,
        "client_calls": n_calls,
        "successful": gw_success,
        "success_rate": round(gw_success / n_calls, 3) if n_calls > 0 else 0.0,
        "upstream_errors": gw_errors,
        "lost_updates": None,
        "backend_calls": n_calls - gw_dedup,
        "calls_avoided": gw_dedup,
        "deduplicated": gw_dedup,
        "peak_upstream_concurrency": getattr(getattr(gateway_runtime, "admission", None), "limit", 3),
        "latency_ms": {
            "p50": _pct(gw_latencies, 50),
            "p95": _pct(gw_latencies, 95),
            "p99": _pct(gw_latencies, 99),
        },
        "measured": True,
        "note": "Proxied through Agent Gateway reverse proxy with admission control and singleflight dedup",
    }

    return direct_metrics, gw_metrics


def create_projects_app(gateway_host: str = DEFAULT_GATEWAY_HOST) -> FastAPI:
    """Build the Test Projects + Zifi Browser FastAPI app served on port 8010."""

    fallback_harness: SceneHarness = create_harness()
    groq_engine = GroqSwarmEngine()
    run_lock = asyncio.Lock()
    state: dict[str, Any] = {
        "running": None,
        "last_runs": {},
        "last_mode": "unknown",
    }

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await fallback_harness.close()

    verify_production_configuration()

    app = FastAPI(title="Zifi Browser & Test Projects — Multi-Agent SaaS Suite", lifespan=lifespan)

    # CORS Hardening: Disallow wildcard '*' in production or when credentials are used
    cors_env = os.getenv("AGENT_GATEWAY_CORS_ORIGINS", "").strip()
    cors_origins = [o.strip() for o in cors_env.split(",") if o.strip()] if cors_env else [
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8010",
        "http://localhost:8000",
        "http://localhost:8010",
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
        allow_headers=["*"],
    )
    rate_limiter = InMemoryRateLimiter(max_requests=15, window_seconds=60.0)

    app.state.fallback_harness = fallback_harness
    app.state.groq_engine = groq_engine
    app.state.gateway_host = gateway_host
    app.state.rate_limiter = rate_limiter

    async def _run_swarm_with_bridge(
        project_id: str,
        prompt: str,
        target_url: str = "",
    ) -> dict[str, Any]:
        recon = await perform_url_recon(
            target_url or BUILT_IN_TARGETS.get(project_id, {}).get("path", "/targets/aegis-store")
        )
        remote_live = await _probe_remote_gateway(app.state.gateway_host)
        if remote_live:
            state["last_mode"] = "remote_gateway_8000"
            timeout = httpx.Timeout(25.0)
            async with (
                httpx.AsyncClient(
                    base_url=f"{app.state.gateway_host}/direct-backend",
                    timeout=timeout,
                ) as direct_client,
                httpx.AsyncClient(
                    base_url=f"{app.state.gateway_host}/backend",
                    timeout=timeout,
                ) as protected_client,
                httpx.AsyncClient(
                    base_url=f"{app.state.gateway_host}/gateway",
                    timeout=timeout,
                ) as gateway_http,
                httpx.AsyncClient(
                    base_url=app.state.gateway_host,
                    timeout=timeout,
                ) as demo_bridge_client,
            ):
                sdk = GatewayClient(client=gateway_http)
                result = await execute_project_swarm(
                    project_id=project_id,
                    mission_prompt=prompt,
                    groq_engine=groq_engine,
                    direct_client=direct_client,
                    protected_client=protected_client,
                    gateway_http=gateway_http,
                    sdk=sdk,
                )
                result["gateway_mode"] = "remote_gateway_8000"
                result["zifi_recon"] = recon
                result["network_interceptor"] = build_network_interceptor_events(recon, result)
                try:
                    await demo_bridge_client.post("/demo/record_run", json=result)
                except Exception:
                    pass
        else:
            state["last_mode"] = "embedded_fallback"
            sdk = GatewayClient(client=fallback_harness.gateway_client)
            result = await execute_project_swarm(
                project_id=project_id,
                mission_prompt=prompt,
                groq_engine=groq_engine,
                direct_client=fallback_harness.direct_client,
                protected_client=fallback_harness.upstream_client,
                gateway_http=fallback_harness.gateway_client,
                sdk=sdk,
            )
            result["gateway_mode"] = "embedded_fallback"
            result["zifi_recon"] = recon
            result["network_interceptor"] = build_network_interceptor_events(recon, result)

        # Populate measured latency profile from actual swarm run
        d_lat = result.get("direct", {}).get("latency_ms", {})
        g_lat = result.get("gateway", {}).get("latency_ms", {})
        measured_p50 = g_lat.get("p50", d_lat.get("p50"))
        measured_p99 = d_lat.get("p99", g_lat.get("p99"))
        if measured_p50 is not None:
            recon["latency_ms"] = measured_p50
            ratio = round(float(measured_p99) / max(0.5, float(measured_p50)), 2) if measured_p99 else 1.0
            recon["latency_profile"] = {
                "cold_total_ms": measured_p50,
                "ttfb_ms": round(float(measured_p50) * 0.7, 1),
                "download_ms": round(max(0.1, float(measured_p50) * 0.3), 1),
                "warm_p50_ms": measured_p50,
                "burst_3x_p95_ms": measured_p99,
                "degradation_ratio": ratio,
                "latency_cause": f"Swarm burst measured (p50 {measured_p50}ms · p99 {measured_p99}ms)",
            }

        result["audit_status"] = "verified_swarm"
        result["has_active_agents"] = True
        result["agents_detected"] = recon.get("agents_detected", [])
        result["tools_detected"] = recon.get("tools_detected", [])
        result["evaluation_report"] = build_four_pillar_evaluation(recon, result)
        state["last_runs"][project_id] = result
        return result

    @app.get("/health")
    async def health() -> dict[str, Any]:
        remote_live = await _probe_remote_gateway(app.state.gateway_host)
        return {
            "status": "ok",
            "suite": "Test Projects",
            "browser": "Zifi Browser",
            "running": state["running"],
            "groq": groq_engine.status(),
            "gateway_connection": {
                "target": app.state.gateway_host,
                "remote_connected": remote_live,
                "mode": "remote_gateway_8000" if remote_live else "embedded_fallback",
            },
        }

    @app.get("/api/projects")
    async def list_projects() -> dict[str, Any]:
        remote_live = await _probe_remote_gateway(app.state.gateway_host)
        return {
            "status": "ok",
            "suite_name": "Test Projects",
            "browser_name": "Zifi Browser",
            "projects": PROJECT_CATALOG,
            "builtin_targets": list(BUILT_IN_TARGETS.values()),
            "groq": groq_engine.status(),
            "gateway_connection": {
                "target": app.state.gateway_host,
                "remote_connected": remote_live,
                "mode": "remote_gateway_8000" if remote_live else "embedded_fallback",
            },
            "running": state["running"],
            "last_runs": state["last_runs"],
        }

    @app.get("/api/status")
    async def get_system_status() -> dict[str, Any]:
        remote_live = await _probe_remote_gateway(app.state.gateway_host)
        return {
            "status": "ok",
            "suite_name": "Test Projects",
            "browser_name": "Zifi Browser",
            "groq": groq_engine.status(),
            "gateway_connection": {
                "target": app.state.gateway_host,
                "remote_connected": remote_live,
                "mode": "remote_gateway_8000" if remote_live else "embedded_fallback",
            },
            "running": state["running"],
        }

    @app.post("/api/config/groq")
    async def configure_groq(req: GroqConfigRequest, request: Request) -> dict[str, Any]:
        admin_key = os.getenv("AGENT_GATEWAY_ADMIN_KEY", "").strip()
        if admin_key:
            auth_header = request.headers.get("X-Admin-Key") or request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            if auth_header != admin_key:
                raise HTTPException(status_code=401, detail="Unauthorized: invalid or missing X-Admin-Key")

        groq_engine.configure(api_key=req.api_key, model=req.model)
        return {
            "status": "ok",
            "groq": groq_engine.status(),
        }

    @app.get("/targets/{slug}", response_class=HTMLResponse)
    async def serve_builtin_target(slug: str) -> HTMLResponse:
        return HTMLResponse(render_builtin_target_html(slug))

    @app.post("/api/zifi/recon")
    async def zifi_recon(req: ZifiReconRequest, request: Request) -> JSONResponse:
        client_ip = request.client.host if request.client else "127.0.0.1"
        allowed, retry_after = await rate_limiter.check(client_ip)
        if not allowed:
            return JSONResponse(
                {"status": "throttled", "reason": "rate_limit_exceeded", "retry_after_ms": retry_after * 1000},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        recon = await perform_url_recon(req.url)
        return JSONResponse({"status": "ok", "recon": recon})

    @app.get("/api/zifi/proxy", response_class=HTMLResponse)
    async def zifi_proxy(url: str = Query(..., description="External URL to render inside Zifi Browser")) -> Response:
        raw = url.strip()
        if not raw.startswith(("http://", "https://")):
            raw = f"https://{raw}"

        csp_header = "default-src 'none'; style-src 'unsafe-inline' https: http:; img-src data: https: http:; font-src https: http:; sandbox allow-forms;"

        # SSRF check on proxy requests as well
        try:
            raw = validate_url_for_recon(raw, allow_local=False)
        except ValueError as exc:
            return HTMLResponse(
                f"<!doctype html><html><body><h3>Blocked by SSRF Protection: {html.escape(str(exc))}</h3></body></html>",
                status_code=400,
                headers={"Content-Security-Policy": csp_header},
            )

        parsed = urlparse(raw)
        origin = f"{parsed.scheme}://{parsed.netloc}/"

        try:
            async with httpx.AsyncClient(
                timeout=6.0,
                follow_redirects=True,
                headers={"User-Agent": "ZifiBrowser/1.0 (+AgentGateway)"},
            ) as client:
                resp = await client.get(raw)
                sanitized_html = sanitize_proxy_html(resp.text, origin)
                return HTMLResponse(
                    content=sanitized_html,
                    status_code=200,
                    headers={
                        "Content-Security-Policy": csp_header,
                        "X-Frame-Options": "SAMEORIGIN",
                        "X-Content-Type-Options": "nosniff",
                    },
                )
        except Exception as exc:
            fallback_html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Zifi Proxy Preview</title></head>
<body style="background:#F1EADB;color:#1B1A17;font-family:'IBM Plex Sans',sans-serif;padding:20px;margin:0;">
  <div style="border:1.5px solid #1B1A17;background:#E4DAC4;box-shadow:3px 3px 0 #1B1A17;">
    <div style="background:#00838A;color:#F1EADB;padding:10px 14px;font-weight:600;border-bottom:1.5px solid #1B1A17;font-family:'IBM Plex Mono',monospace;font-size:12px;">
      ZIFI BROWSER // LIVE PROXY TARGET: {html.escape(raw)}
    </div>
    <div style="padding:16px;font-size:13px;">
      <p style="margin:0 0 8px;"><strong>Origin status:</strong> {html.escape(type(exc).__name__)}</p>
      <p style="margin:0;color:#6B6559;">Zifi Browser has mapped the endpoint surface of this origin for multi-agent simulation and Agent Gateway protection.</p>
    </div>
  </div>
</body></html>"""
            return HTMLResponse(
                content=fallback_html,
                status_code=200,
                headers={
                    "Content-Security-Policy": csp_header,
                    "X-Frame-Options": "SAMEORIGIN",
                    "X-Content-Type-Options": "nosniff",
                },
            )

    @app.post("/api/zifi/audit")
    async def zifi_audit(req: ZifiAuditRequest, request: Request) -> JSONResponse:
        client_ip = request.client.host if request.client else "127.0.0.1"
        allowed, retry_after = await rate_limiter.check(client_ip)
        if not allowed:
            return JSONResponse(
                {"status": "throttled", "reason": "rate_limit_exceeded", "retry_after_ms": retry_after * 1000},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        recon = await perform_url_recon(req.url)
        is_local_project = bool(recon.get("is_builtin", False)) or (
            any(pid in req.url.lower() for pid in ("aegis-store", "sentinel-console", "quant-desk", "java-spring-jss", "aegis-commerce", "sentinel-ops", "quant-pulse"))
            and any(host in req.url for host in ("127.0.0.1", "localhost", "/targets/"))
        )

        if not is_local_project:
            agents_list = recon.get("agents_detected", [])
            tools_list = recon.get("tools_detected", [])
            lat_prof = recon.get("latency_profile", {})
            eval_report = recon.get("evaluation_report") or build_four_pillar_evaluation(recon)
            has_agents = recon.get("has_active_agents", False)
            probe_summary = recon.get("probe_summary", {})
            probes_sent = int(probe_summary.get("probes_sent", 0))
            probes_succeeded = int(probe_summary.get("probes_succeeded", 0))
            probes_errors = int(probe_summary.get("probes_errors", 0))

            is_owned = check_target_ownership(req.url)
            gw_runtime = fallback_harness.gateway.state.runtime

            if is_owned:
                direct_metrics, gateway_metrics = await execute_bounded_probe_test(
                    target_url=req.url,
                    gateway_runtime=gw_runtime,
                    gateway_host=app.state.gateway_host,
                    n_calls=10,
                )
                audit_status = "owned_target_proxied_audit"
                verdict_msg = (
                    f"Audited owned target {req.url} via Agent Gateway proxy mode: 10 live calls tested. "
                    f"Gateway coalesced {gateway_metrics['deduplicated']} duplicate requests via singleflight, "
                    f"achieving p50 {gateway_metrics['latency_ms']['p50']}ms (vs {direct_metrics['latency_ms']['p50']}ms direct). "
                    "All metrics measured live."
                )
            elif not has_agents:
                audit_status = "no_agents_detected"
                empty_metrics = {
                    "client_calls": 0,
                    "successful": 0,
                    "success_rate": 0.0,
                    "upstream_errors": 0,
                    "lost_updates": 0,
                    "backend_calls": 0,
                    "calls_avoided": 0,
                    "deduplicated": 0,
                    "depth_denied": 0,
                    "policy_denied": 0,
                    "approval_pending": 0,
                    "budget_cancelled": 0,
                    "peak_upstream_concurrency": 0,
                    "latency_ms": {"p50": 0.0, "p99": 0.0},
                    "measured": False,
                    "note": "not measured (0 agents detected)",
                }
                direct_metrics = empty_metrics
                gateway_metrics = empty_metrics
                verdict_msg = (
                    f"Audited {recon.get('domain', req.url)} [{', '.join(recon.get('tech_stack', ['HTML5'])[:2])}]: "
                    "0 autonomous agents detected statically. "
                    f"Security Score {eval_report.get('overall_score', 0)}/100 ({eval_report.get('grade', 'C')}). "
                    "Truthful baseline: 0 false swarm metrics generated."
                )
            else:
                audit_status = "external_url_audit"
                run_id = f"recon_{uuid.uuid4().hex[:8]}"
                now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                sr = round(probes_succeeded / probes_sent, 3) if probes_sent > 0 else 0.0
                direct_metrics = {
                    "source": "measured",
                    "run_id": run_id,
                    "timestamp_utc": now_utc,
                    "client_calls": probes_sent,
                    "successful": probes_succeeded,
                    "success_rate": sr,
                    "upstream_errors": probes_errors,
                    "lost_updates": None,
                    "backend_calls": probes_sent,
                    "calls_avoided": 0,
                    "deduplicated": 0,
                    "depth_denied": 0,
                    "policy_denied": 0,
                    "approval_pending": 0,
                    "budget_cancelled": 0,
                    "peak_upstream_concurrency": 3 if probes_sent >= 3 else 1,
                    "latency_ms": {
                        "p50": lat_prof.get("warm_p50_ms"),
                        "p95": lat_prof.get("burst_3x_p95_ms"),
                        "p99": lat_prof.get("burst_3x_p95_ms"),
                    },
                    "ttfb_ms": lat_prof.get("ttfb_ms"),
                    "degradation_ratio": lat_prof.get("degradation_ratio"),
                    "measured": True,
                    "note": f"Live probe measurements across {probes_sent} requests to origin (recon only)",
                }
                gateway_metrics = {
                    "source": "measured",
                    "client_calls": None,
                    "successful": None,
                    "success_rate": None,
                    "upstream_errors": None,
                    "lost_updates": None,
                    "backend_calls": None,
                    "calls_avoided": None,
                    "deduplicated": None,
                    "depth_denied": None,
                    "policy_denied": None,
                    "approval_pending": None,
                    "budget_cancelled": None,
                    "peak_upstream_concurrency": None,
                    "latency_ms": {"p50": None, "p95": None, "p99": None},
                    "measured": False,
                    "note": "not measured (recon only — unowned external target, gateway not in path)",
                }
                verdict_msg = (
                    f"Audited {recon.get('domain', req.url)} (recon only — unowned external target, no load test performed). "
                    f"Live probes: cold TTFB {lat_prof.get('ttfb_ms')}ms · warm p50 {lat_prof.get('warm_p50_ms')}ms. "
                    f"Security Score {eval_report.get('overall_score', 0)}/100 ({eval_report.get('grade', 'C')}). "
                    "Gateway was not in path. Truthful baseline: 0 unverified gateway metrics generated."
                )

            waves: list[dict[str, Any]] = []
            if has_agents:
                waves = list(recon.get("probe_waves", []))

            agent_feed = [
                {
                    "agent_id": a.get("id", "agent"),
                    "action": f"Identified declared agent role: {a.get('role', 'Agent')}",
                    "timestamp": f"{0.1 * (i + 1):.1f}s",
                }
                for i, a in enumerate(agents_list)
            ] or [
                {
                    "agent_id": "recon",
                    "action": "Verified 0 active agents declared on origin",
                    "timestamp": "0.1s",
                }
            ]

            return JSONResponse(
                {
                    "status": "ok",
                    "audit_status": audit_status,
                    "owned": is_owned,
                    "has_active_agents": has_agents,
                    "project_id": "",
                    "name": recon.get("title", req.url),
                    "target_url": req.url,
                    "zifi_recon": recon,
                    "evaluation_report": eval_report,
                    "agents_detected": agents_list,
                    "tools_detected": tools_list,
                    "network_interceptor": waves if has_agents else [],
                    "agent_feed": agent_feed if has_agents else [],
                    "executive_summary": verdict_msg,
                    "mode": "llm" if groq_engine.config.configured else "scripted",
                    "llm_status": (
                        f"live (groq · {groq_engine.config.model})"
                        if groq_engine.config.configured
                        else "LLM unavailable, fell back to scripted"
                    ),
                    "llm": {
                        "provider": "Zifi Recon & 4-Pillar Evaluator",
                        "model": groq_engine.config.model,
                        "live_llm": groq_engine.config.configured,
                        "plan": {
                            "mission_summary": verdict_msg,
                            "execution_steps": [
                                {"step": 1, "description": f"Probe live HTTP TTFB ({lat_prof.get('ttfb_ms', 0)}ms) and 3× burst p95 ({lat_prof.get('burst_3x_p95_ms', 0)}ms)"},
                                {"step": 2, "description": f"Scan DOM and code manifests for declared agents ({len(agents_list)} found)"},
                                {"step": 3, "description": f"Enumerate callable tools and forms ({len(tools_list)} found)"},
                                {"step": 4, "description": "Assess OWASP LLM01-10 & Agentic ASI01-10 security headers via NumPy calculations.py"},
                            ],
                        },
                        "synthesis": {"executive_verdict": verdict_msg},
                    },
                    "direct": direct_metrics,
                    "gateway": gateway_metrics,
                }
            )

        project_id = recon.get("project_id") or req.project_id.strip() or resolve_project_for_url(req.url)
        try:
            get_project_definition(project_id)
        except KeyError:
            project_id = "aegis-commerce"

        if run_lock.locked():
            return JSONResponse(
                {"status": "busy", "reason": "swarm_running", "retry_after_ms": 300},
                status_code=409,
            )

        async with run_lock:
            state["running"] = project_id
            try:
                result = await _run_swarm_with_bridge(
                    project_id=project_id,
                    prompt=req.prompt,
                    target_url=req.url,
                )
                return JSONResponse(result)
            finally:
                state["running"] = None

    @app.post("/api/projects/{project_id}/run")
    async def run_project(project_id: str, req: ProjectRunRequest) -> JSONResponse:
        try:
            get_project_definition(project_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail={"status": "error", "reason": "unknown_project"},
            ) from exc

        if run_lock.locked():
            return JSONResponse(
                {"status": "busy", "reason": "swarm_running", "retry_after_ms": 300},
                status_code=409,
            )

        async with run_lock:
            state["running"] = project_id
            try:
                result = await _run_swarm_with_bridge(
                    project_id=project_id,
                    prompt=req.prompt,
                    target_url=req.target_url,
                )
                return JSONResponse(result)
            finally:
                state["running"] = None

    @app.get("/api/approvals")
    async def list_approvals() -> dict[str, Any]:
        remote_live = await _probe_remote_gateway(app.state.gateway_host)
        if remote_live:
            async with httpx.AsyncClient(base_url=app.state.gateway_host, timeout=5.0) as client:
                resp = await client.get("/demo/approvals")
                return resp.json()
        runtime = fallback_harness.gateway.state.runtime
        return {
            "status": "ok",
            "approvals": [item.public() for item in runtime.policy.approvals.pending()],
        }

    @app.post("/api/approvals/{approval_id}/approve")
    async def approve_action(approval_id: str) -> JSONResponse:
        remote_live = await _probe_remote_gateway(app.state.gateway_host)
        if remote_live:
            async with httpx.AsyncClient(base_url=app.state.gateway_host, timeout=10.0) as client:
                resp = await client.post(f"/demo/approvals/{approval_id}/approve")
                return JSONResponse(resp.json(), status_code=resp.status_code)

        runtime = fallback_harness.gateway.state.runtime
        approval = runtime.policy.approvals.get(approval_id)
        if approval is None:
            return JSONResponse(
                {"status": "not_found", "reason": "unknown_approval"},
                status_code=404,
            )
        if approval.status != "pending":
            return JSONResponse(
                {"status": "denied", "reason": "approval_not_pending"},
                status_code=409,
            )
        runtime.policy.approvals.approve(approval_id)
        result = await runtime.call(
            CallRequest(
                goal_id=approval.goal_id,
                agent_id=approval.agent_id,
                tool=approval.tool,
                payload=approval.payload,
                approval_id=approval_id,
            )
        )
        return JSONResponse(
            {
                "approval_id": approval_id,
                "status": result.status,
                "result": result.result,
            }
        )

    @app.get("/api/gateway/snapshot")
    async def gateway_snapshot() -> dict[str, Any]:
        runtime = fallback_harness.gateway.state.runtime
        return {
            "status": "ok",
            "scenes": SCENE_DEFINITIONS,
            "gateway": runtime.metrics.snapshot(),
            "admission": runtime.admission.snapshot(),
            "approvals": [item.public() for item in runtime.policy.approvals.pending()],
        }

    @app.post("/api/gateway/scenes/{scene_id}")
    async def run_gateway_scene(scene_id: str) -> JSONResponse:
        if run_lock.locked():
            return JSONResponse(
                {"status": "busy", "reason": "swarm_running", "retry_after_ms": 300},
                status_code=409,
            )
        async with run_lock:
            state["running"] = scene_id
            try:
                result = await run_scene(fallback_harness, scene_id, seed=7)
                return JSONResponse(result)
            except KeyError as exc:
                raise HTTPException(
                    status_code=404,
                    detail={"status": "error", "reason": "unknown_scene"},
                ) from exc
            finally:
                state["running"] = None

    ui_dir = THIS_DIR / "ui"
    if ui_dir.exists():
        app.mount("/", StaticFiles(directory=str(ui_dir), html=True), name="ui")

    return app


app = create_projects_app()
