"""Zifi Browser backend engine: URL Reconnaissance, Server-Side Proxy, and Built-In Target Web Apps.

Powers the 'Zifi Browser' experience inside the Test Projects SaaS platform:
1. Built-in realistic target web applications (/targets/aegis-store, /targets/sentinel-console,
   /targets/quant-desk) with real interactive forms, live counters, and postMessage hooks for the
   Zifi Agent Activity Overlay.
2. Server-side URL Reconnaissance (/api/zifi/recon) that inspects any pasted URL (status, latency,
   headers, forms, buttons, links, API surfaces, and frame-blocking headers).
3. Server-side HTML Proxy (/api/zifi/proxy?url=...) that strips X-Frame-Options / CSP frame-ancestors,
   injects a <base> tag so assets resolve, and enables any site to render inside the Zifi Browser viewport.
"""

from __future__ import annotations

import asyncio
import html
import ipaddress
import json
import os
import re
import socket
import time
from typing import Any
from urllib.parse import urljoin, urlparse, urlsplit

import httpx

# All numeric computation is delegated to calculations.py — no LLM math.
from calculations import (
    benchmark_overall_score,
    compute_evidence_confidence,
    evaluate_gateway_effect,
    evaluate_site_posture,
    four_pillar_score,
    latency_degradation_ratio,
    latency_waterfall_summary,
    STATUS_WEIGHTS,
)
try:
    from scorecard_spec import SCORECARD_SPECS, get_spec_by_row_id
except ImportError:
    from .scorecard_spec import SCORECARD_SPECS, get_spec_by_row_id


def validate_url_for_recon(url: str, allow_local: bool = False) -> str:
    """Validate a target URL for SSRF protection before any network probe.

    Blocks:
    - Schemes other than http/https
    - URL user:password credentials
    - Link-local (169.254.0.0/16 including AWS/GCP metadata)
    - Private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.)
    - IPv6 loopback (::1), link-local (fe80::/10), unique local (fc00::/7), and IPv4-mapped IPv6
    - Decimal, octal, and hex representations of private/loopback IPs
    """
    raw = (url or "").strip()
    if not raw.startswith(("http://", "https://", "file://", "ftp://", "gopher://")):
        raw = f"https://{raw}"

    parsed = urlsplit(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"Scheme disallowed: '{scheme}' is not permitted (only http/https)")

    if parsed.username or parsed.password:
        raise ValueError("SSRF blocked: URL credentials (user:pass@) are disallowed")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError("SSRF blocked: missing hostname in URL")

    # If allow_local is explicitly enabled for internal demo testing
    if allow_local and hostname in {"127.0.0.1", "localhost", "::1"}:
        return raw

    # Check for direct decimal/hex/octal integer IP encodings (octal before decimal isdigit)
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

    # Resolve hostname to IP addresses
    if not ip_candidates:
        try:
            ip_obj = ipaddress.ip_address(hostname)
            ip_candidates.append(str(ip_obj))
        except ValueError:
            try:
                addr_info = socket.getaddrinfo(hostname, None)
                for item in addr_info:
                    ip_candidates.append(item[4][0])
            except socket.gaierror as exc:
                raise ValueError(f"SSRF blocked: DNS resolution failed for '{hostname}': {exc}")

    if not ip_candidates:
        raise ValueError(f"SSRF blocked: unable to resolve host '{hostname}'")

    for ip_str in ip_candidates:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise ValueError(f"SSRF blocked: invalid resolved IP '{ip_str}'")

        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped

        if ip_obj.is_loopback:
            raise ValueError(f"SSRF blocked: host '{hostname}' resolves to loopback IP '{ip_str}'")
        if ip_obj.is_link_local or str(ip_obj) == "169.254.169.254":
            raise ValueError(f"SSRF blocked: host '{hostname}' resolves to cloud metadata/link-local IP '{ip_str}'")
        if ip_obj.is_private:
            raise ValueError(f"SSRF blocked: host '{hostname}' resolves to private IP '{ip_str}'")
        if ip_obj.is_multicast:
            raise ValueError(f"SSRF blocked: host '{hostname}' resolves to multicast IP '{ip_str}'")
        if ip_obj.is_reserved or ip_obj.is_unspecified:
            raise ValueError(f"SSRF blocked: host '{hostname}' resolves to reserved IP '{ip_str}'")

    return raw

BUILT_IN_TARGETS: dict[str, dict[str, Any]] = {
    "aegis-commerce": {
        "project_id": "aegis-commerce",
        "slug": "aegis-store",
        "path": "/targets/aegis-store",
        "title": "Aegis Commerce — Flash Sale & VIP Order Portal",
        "domain": "store.aegis-commerce.internal",
        "category": "E-Commerce & Order Operations",
        "tech_stack": [
            "HTML5 / Risograph UI",
            "FastAPI Async Backend",
            "React / JSS Component Styles",
            "LangGraph + Groq Swarm Runtime",
        ],
        "agents": [
            {"id": "orchestrator-aegis", "role": "Order Operations Lead Agent", "kind": "agent", "tools": ["read"], "source": "swarm_manifest"},
            {"id": "reader-00..35", "role": "36× Catalog & Order Reader Sub-Agents", "kind": "agent", "tools": ["read"], "source": "swarm_manifest"},
            {"id": "writer-00..07", "role": "8× Fenced Inventory Ledger Writers", "kind": "agent", "tools": ["guarded_write"], "source": "swarm_manifest"},
            {"id": "tracer-d1..d4", "role": "Recursive Shipment Hop Tracers (2^d)", "kind": "agent", "tools": ["read (tree)"], "source": "swarm_manifest"},
            {"id": "reader-audit-01", "role": "Read-Only Compliance Verifier", "kind": "agent", "tools": ["delete (blocked)"], "source": "swarm_manifest"},
            {"id": "support-lead-01", "role": "VIP Dispute & Refund Specialist", "kind": "agent", "tools": ["refund"], "source": "swarm_manifest"},
        ],
        "endpoints": [
            {"name": "read_order_catalog", "kind": "tool", "method": "GET", "path": "/api/orders/order-hot-901", "risk": "High Burst Read (Duplicate Storm)"},
            {"name": "reserve_inventory_sku", "kind": "tool", "method": "POST", "path": "/api/inventory/sku-flash-77/reserve", "risk": "Concurrent Write Race (Lost Updates)"},
            {"name": "trace_shipment_hop", "kind": "tool", "method": "GET", "path": "/api/shipments/trace-hop", "risk": "Recursive Sub-Agent Fan-Out"},
            {"name": "issue_vip_refund", "kind": "tool", "method": "POST", "path": "/api/refunds/issue", "risk": "High-Value Financial Action ($280)"},
            {"name": "purge_audit_log", "kind": "tool", "method": "DELETE", "path": "/api/compliance/audit-log", "risk": "Destructive Mutation"},
        ],
    },
    "sentinel-ops": {
        "project_id": "sentinel-ops",
        "slug": "sentinel-console",
        "path": "/targets/sentinel-console",
        "title": "Sentinel Ops — Kubernetes & Cloud Incident Console",
        "domain": "console.sentinel-ops.internal",
        "category": "DevOps & Cloud Infrastructure",
        "tech_stack": [
            "HTML5 / Cloud Ops UI",
            "FastAPI / OpenTelemetry GenAI",
            "JSS / Emotion Styles",
            "MCP Server + Autonomous Incident Swarm",
        ],
        "agents": [
            {"id": "orchestrator-sentinel", "role": "Incident Commander Agent", "kind": "agent", "tools": ["read"], "source": "swarm_manifest"},
            {"id": "reader-00..47", "role": "48× Telemetry Poller Sub-Agents", "kind": "agent", "tools": ["read"], "source": "swarm_manifest"},
            {"id": "writer-00..11", "role": "12× Replica State Mutators", "kind": "agent", "tools": ["guarded_write"], "source": "swarm_manifest"},
            {"id": "tracer-d1..d4", "role": "Recursive Service-Mesh Hop Tracers", "kind": "agent", "tools": ["read (tree)"], "source": "swarm_manifest"},
            {"id": "reader-audit-01", "role": "Read-Only Security Scanner", "kind": "agent", "tools": ["delete (blocked)"], "source": "swarm_manifest"},
            {"id": "support-lead-01", "role": "FinOps SLA Credit Agent", "kind": "agent", "tools": ["refund"], "source": "swarm_manifest"},
        ],
        "endpoints": [
            {"name": "poll_cluster_telemetry", "kind": "tool", "method": "GET", "path": "/api/clusters/prod-us-east-1/telemetry", "risk": "High Burst Read (Duplicate Storm)"},
            {"name": "increment_runbook_state", "kind": "tool", "method": "POST", "path": "/api/runbooks/state/increment", "risk": "Concurrent Config Drift (Write Race)"},
            {"name": "trace_mesh_dependencies", "kind": "tool", "method": "GET", "path": "/api/mesh/dependency-trace", "risk": "Recursive Microservice Hop Loop"},
            {"name": "issue_sla_credit", "kind": "tool", "method": "POST", "path": "/api/billing/sla-credit", "risk": "High-Value SLA Credit ($320)"},
            {"name": "delete_vault_secrets", "kind": "tool", "method": "DELETE", "path": "/api/vault/production-secrets", "risk": "Destructive Mutation"},
        ],
    },
    "quant-pulse": {
        "project_id": "quant-pulse",
        "slug": "quant-desk",
        "path": "/targets/quant-desk",
        "title": "QuantPulse — Institutional Order Book & NAV Terminal",
        "domain": "terminal.quantpulse.internal",
        "category": "Quantitative Finance & Treasury",
        "tech_stack": [
            "Java / Spring Boot 3.4 + Spring AI",
            "LangChain4j AiServices + MCP SSE (/mcp/message)",
            "JSS (CSS-in-JS makeStyles) + Jakarta Faces (JSF/JSP)",
            "High-Frequency Order-Book Swarm",
        ],
        "agents": [
            {"id": "orchestrator-quant", "role": "Desk Risk Orchestrator Agent", "kind": "agent", "tools": ["read"], "source": "swarm_manifest"},
            {"id": "reader-00..63", "role": "64× Order-Book & Factor Readers", "kind": "agent", "tools": ["read"], "source": "swarm_manifest"},
            {"id": "writer-00..15", "role": "16× NAV Margin Lot Writers", "kind": "agent", "tools": ["guarded_write"], "source": "swarm_manifest"},
            {"id": "tracer-d1..d4", "role": "Recursive Counterparty Chain Tracers", "kind": "agent", "tools": ["read (tree)"], "source": "swarm_manifest"},
            {"id": "reader-audit-01", "role": "Read-Only Market Screener", "kind": "agent", "tools": ["delete (blocked)"], "source": "swarm_manifest"},
            {"id": "support-lead-01", "role": "Treasury Wire Settlement Agent", "kind": "agent", "tools": ["refund"], "source": "swarm_manifest"},
        ],
        "endpoints": [
            {"name": "read_nvda_order_book", "kind": "tool", "method": "GET", "path": "/api/quotes/ticker-NVDA-book", "risk": "High Burst Read (Market Feed Storm)"},
            {"name": "adjust_nav_ledger", "kind": "tool", "method": "POST", "path": "/api/ledger/nav-adjust", "risk": "Concurrent Ledger Race (Lost Updates)"},
            {"name": "trace_counterparty_chain", "kind": "tool", "method": "GET", "path": "/api/exposure/counterparty-chain", "risk": "Recursive Derivative Tree"},
            {"name": "execute_wire_settlement", "kind": "tool", "method": "POST", "path": "/api/treasury/wire-settlement", "risk": "High-Notional Wire ($450)"},
            {"name": "purge_trade_blotter", "kind": "tool", "method": "DELETE", "path": "/api/compliance/trade-blotter", "risk": "Destructive Mutation"},
        ],
    },
    "java-spring-jss": {
        "project_id": "java-spring-jss",
        "slug": "java-spring-jss",
        "path": "/targets/java-spring-jss",
        "title": "Java Spring AI + JSS / Jakarta EE Enterprise Portal",
        "domain": "enterprise.spring-ai-jss.internal",
        "category": "Java / Spring Boot / LangChain4j / JSS Stack",
        "tech_stack": [
            "Java 21 · Spring Boot 3.4 · Spring MVC / Actuator",
            "Spring AI ChatClient + LangChain4j @AiService (/mcp/message, /sse)",
            "Jakarta EE · JSP (.jsp/.do) · JSF PrimeFaces (jakarta.faces.ViewState)",
            "JSS (CSS-in-JS data-jss / makeStyles) + React/MUI Frontend",
        ],
        "agents": [
            {"id": "spring-ai-orchestrator", "role": "Spring AI ChatClient Orchestrator (@McpServer)", "kind": "agent", "tools": ["read"], "source": "spring_ai_bean"},
            {"id": "lc4j-reader-00..41", "role": "42× LangChain4j AiServices Catalog Readers", "kind": "agent", "tools": ["read"], "source": "langchain4j_service"},
            {"id": "jpa-writer-00..09", "role": "10× Hibernate/JPA Optimistic-Lock Ledger Writers", "kind": "agent", "tools": ["guarded_write"], "source": "spring_data_jpa"},
            {"id": "mcp-tracer-d1..d4", "role": "Recursive Spring AI MCP Tool Hop Tracers (2^d)", "kind": "agent", "tools": ["read (tree)"], "source": "spring_ai_mcp_sse"},
            {"id": "jsf-audit-reader-01", "role": "Jakarta Security Read-Only Compliance Auditor", "kind": "agent", "tools": ["delete (blocked)"], "source": "jakarta_security"},
            {"id": "treasury-approver-01", "role": "Spring Security @PreAuthorize Settlement Agent", "kind": "agent", "tools": ["refund"], "source": "spring_security"},
        ],
        "endpoints": [
            {"name": "spring_order_catalog_jsp", "kind": "tool", "method": "GET", "path": "/api/v3/orders/catalog.jsp", "risk": "High Burst Read (36× Spring AI Pollers)"},
            {"name": "jsf_inventory_mutate_do", "kind": "tool", "method": "POST", "path": "/inventory/reserveStock.do", "risk": "Concurrent JPA Write Race (Lost Updates)"},
            {"name": "mcp_sse_trace_hop", "kind": "tool", "method": "GET", "path": "/mcp/message/trace-hop", "risk": "Recursive LangChain4j Sub-Agent Loop"},
            {"name": "spring_ai_wire_refund", "kind": "tool", "method": "POST", "path": "/api/settlement/issueRefund.action", "risk": "High-Value Financial Action ($280)"},
            {"name": "actuator_audit_purge", "kind": "tool", "method": "DELETE", "path": "/actuator/audit-log/purge", "risk": "Destructive Actuator Mutation"},
        ],
    },
}


def resolve_project_for_url(url: str) -> str:
    """Map a built-in target URL to its project archetype, or return empty for external sites."""
    lowered = (url or "").lower()
    if "sentinel-console" in lowered or "sentinel-ops" in lowered:
        return "sentinel-ops"
    if "quant-desk" in lowered or "quant-pulse" in lowered:
        return "quant-pulse"
    if "java-spring-jss" in lowered:
        return "java-spring-jss"
    if "aegis-store" in lowered or "aegis-commerce" in lowered:
        return "aegis-commerce"
    return ""


def detect_multi_stack_and_surfaces(
    html_body: str,
    headers_dict: dict[str, str],
    script_bodies: list[str] | None = None,
) -> dict[str, Any]:
    """Detect Frontend/Backend Stacks (HTML, Java/Spring/JSP/JSF/Vaadin, JSS/CSS-in-JS, React/Vue/Angular)
    and separate autonomous Agents from callable Tools.

    Never fabricates agents or tools when scanning non-agent websites.
    """
    combined_source = html_body + "\n" + "\n".join(script_bodies or [])
    agents: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    detected_stacks: list[str] = []
    java_extensions: list[str] = []
    jss_and_ui_libs: list[str] = []

    set_cookie = headers_dict.get("set-cookie", "")
    powered_by = headers_dict.get("x-powered-by", "")
    server_hdr = headers_dict.get("server", "")
    app_ctx = headers_dict.get("x-application-context", "")

    # --- A. Detect Java & Extended JVM Web/UI Frameworks ---
    if (
        "jsessionid" in set_cookie.lower()
        or "jsessionid" in combined_source.lower()
        or "servlet" in powered_by.lower()
        or any(s in server_hdr.lower() for s in ("coyote", "jetty", "wildfly", "undertow", "payara", "glassfish", "netty"))
    ):
        java_extensions.append("Java Servlet / Jakarta EE Runtime (JSESSIONID)")

    if (
        app_ctx
        or re.search(r"/(?:actuator|v3/api-docs|swagger-ui)", combined_source, re.IGNORECASE)
        or re.search(r"\b(?:SpringBoot|SpringMVC|org\.springframework|th:text|th:action)\b", combined_source)
    ):
        java_extensions.append("Spring Boot / Spring MVC / Thymeleaf")

    if re.search(r"\b(?:SpringAI|ChatClient|@McpTool|@McpServer|spring-ai|/mcp/message)\b", combined_source, re.IGNORECASE):
        java_extensions.append("Spring AI (ChatClient / MCP Server SSE)")

    if re.search(r"\b(?:LangChain4j|AiServices|ChatLanguageModel|McpToolProvider|quarkus-langchain4j)\b", combined_source, re.IGNORECASE):
        java_extensions.append("LangChain4j (Declarative AiServices / MCP)")

    if re.search(r'\.(?:jsp|jspx|do|action)\b', combined_source, re.IGNORECASE) or "jsp" in powered_by.lower():
        java_extensions.append("JSP / Struts / Jakarta Server Pages (.jsp / .do / .action)")

    if re.search(r"(?:javax\.faces\.ViewState|jakarta\.faces\.ViewState|PrimeFaces\.cw|\.xhtml\b|\.jsf\b)", combined_source, re.IGNORECASE):
        java_extensions.append("Jakarta Faces (JSF) / PrimeFaces (ViewState)")

    if re.search(r"(?:\bv-app\b|VAADIN/|UIDL|\?v-r=uidl|<vaadin-)", combined_source, re.IGNORECASE):
        java_extensions.append("Vaadin Flow / Hilla JVM UI")

    if re.search(r"(?:\.nocache\.js\b|__gwt_|Wicket\.Ajax|\?wicket:interface)", combined_source, re.IGNORECASE):
        java_extensions.append("GWT / Apache Wicket Component UI")

    # --- B. Detect JSS (CSS-in-JS) & Modern Frontend Libraries ---
    if re.search(r"(?:data-jss\b|makeStyles-|tss-css-|__JSS_STATE__|sitecore-jss|\bjss-\d+)", combined_source, re.IGNORECASE):
        jss_and_ui_libs.append("JSS (CSS-in-JS / makeStyles / Sitecore JSS)")

    if re.search(r"(?:MuiBox-root|MuiButton-root|data-emotion|data-styled|\bsc-[a-zA-Z0-9]{6,}\b)", combined_source):
        jss_and_ui_libs.append("Material-UI (MUI) / Emotion / Styled-Components")

    if re.search(r"(?:__NEXT_DATA__|/_next/static/|data-reactroot|next-action|React\.createElement)", combined_source):
        jss_and_ui_libs.append("React / Next.js")

    if re.search(r"(?:__NUXT__|data-v-[a-f0-9]{6,}|Vue\.createApp)", combined_source, re.IGNORECASE):
        jss_and_ui_libs.append("Vue / Nuxt")

    if re.search(r"(?:ng-version=|_ngcontent-|_nghost-)", combined_source, re.IGNORECASE):
        jss_and_ui_libs.append("Angular")

    if re.search(r"(?:__sveltekit|svelte-[a-z0-9]+)", combined_source, re.IGNORECASE):
        jss_and_ui_libs.append("Svelte / SvelteKit")

    if "<html" in html_body.lower() or "<!doctype html" in html_body.lower():
        detected_stacks.append("HTML5 Document")
    detected_stacks.extend(java_extensions)
    detected_stacks.extend(jss_and_ui_libs)

    # --- B1. Parse JSON Manifests (OpenAPI 3.x / Swagger 2.0 / MCP / A2A) ---
    trimmed = html_body.strip()
    if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
        try:
            parsed_json = json.loads(trimmed)
            if isinstance(parsed_json, dict):
                # 1. OpenAPI 3.x / Swagger 2.0
                if "openapi" in parsed_json or "swagger" in parsed_json:
                    ver = parsed_json.get("openapi") or parsed_json.get("swagger")
                    detected_stacks.append(f"OpenAPI Specification ({ver})")
                    paths = parsed_json.get("paths", {})
                    if isinstance(paths, dict):
                        for p_path, p_methods in paths.items():
                            if isinstance(p_methods, dict):
                                for p_method, p_op in p_methods.items():
                                    if p_method.lower() in ("get", "post", "put", "delete", "patch", "options", "head"):
                                        op_summary = (
                                            p_op.get("summary")
                                            or p_op.get("operationId")
                                            or f"{p_method.upper()} {p_path}"
                                            if isinstance(p_op, dict)
                                            else f"{p_method.upper()} {p_path}"
                                        )
                                        clean_name = f"{p_method.lower()}_{re.sub(r'[^a-zA-Z0-9_]', '_', p_path.strip('/'))}"[:40]
                                        tools.append({
                                            "name": clean_name or "openapi_op",
                                            "kind": "tool",
                                            "method": p_method.upper(),
                                            "method_evidence": "DETECTED",
                                            "path": p_path,
                                            "risk": f"OpenAPI Declared Tool: {op_summary}",
                                            "evidence": "DETECTED",
                                            "source": "openapi_manifest",
                                        })
                # 2. MCP Manifest ({ "tools": [...] })
                if "tools" in parsed_json and isinstance(parsed_json["tools"], list):
                    detected_stacks.append("Model Context Protocol (MCP) Manifest")
                    for m_tool in parsed_json["tools"]:
                        if isinstance(m_tool, dict) and "name" in m_tool:
                            t_name = m_tool["name"]
                            tools.append({
                                "name": t_name,
                                "kind": "tool",
                                "method": "POST",
                                "method_evidence": "INFERRED",
                                "path": f"/mcp/tools/{t_name}",
                                "risk": f"MCP Tool: {m_tool.get('description', t_name)}",
                                "evidence": "DETECTED",
                                "source": "mcp_manifest",
                            })
                # 3. A2A Agent Card Manifest
                if "agent" in parsed_json or "agents" in parsed_json:
                    detected_stacks.append("A2A Protocol Agent Card")
                    raw_agents = parsed_json.get("agents") if isinstance(parsed_json.get("agents"), list) else [parsed_json.get("agent")]
                    for a_item in raw_agents:
                        if isinstance(a_item, dict) and "id" in a_item:
                            agents.append({
                                "id": a_item["id"],
                                "role": a_item.get("role") or a_item.get("description") or "A2A Protocol Agent",
                                "kind": "agent",
                                "tools": a_item.get("tools", []),
                                "source": "a2a_manifest",
                                "evidence": "DETECTED",
                            })
        except Exception:
            pass

    if re.search(r"\b(?:swagger-ui|swagger\.json|openapi\.json|/v3/api-docs)\b", combined_source, re.IGNORECASE):
        if not any("OpenAPI" in s for s in detected_stacks):
            detected_stacks.append("OpenAPI / Swagger UI")

    if not detected_stacks:
        detected_stacks.append("HTTP / JSON Endpoint")

    # --- C. Identify Explicit Autonomous Agents (Headers, DOM, A2A, Spring AI, LangChain4j, JS SDKs) ---
    for h_key, h_val in headers_dict.items():
        if h_key.startswith(("x-agent", "x-swarm", "x-mcp-agent", "x-spring-ai-agent")):
            agents.append(
                {
                    "id": h_val[:40] or h_key,
                    "role": f"Header-Declared Agent ({h_key})",
                    "kind": "agent",
                    "tools": [],
                    "source": f"http_header:{h_key}",
                    "evidence": "DETECTED",
                }
            )

    for match in re.finditer(
        r'data-agent(?:-id|-name|-role)?=["\']([^"\']{1,60})["\']',
        combined_source,
        re.IGNORECASE,
    ):
        agent_id = match.group(1).strip()
        if not any(a["id"] == agent_id for a in agents):
            agents.append(
                {
                    "id": agent_id,
                    "role": "DOM/JSS-Declared Autonomous Agent",
                    "kind": "agent",
                    "tools": [],
                    "source": "dom_data_agent_attr",
                    "evidence": "DETECTED",
                }
            )

    # --- C1. Parse Declared Crew / Swarm Manifests & Individual Sub-Agents ---
    decoded_source = html.unescape(combined_source)

    # 1. Lead Coordinator / Supervisor (e.g. Crew: Manager (LLM: gpt-4.1-mini)...)
    crew_match = re.search(
        r'(?:<strong>)?(?:Crew|Coordinator|Supervisor|Lead Agent)(?:</strong>)?\s*:\s*([^<\n\r]+)',
        decoded_source,
        re.IGNORECASE,
    )
    if crew_match:
        val = crew_match.group(1).strip()
        lead_part = re.split(r',\s*\d+\s+agents', val, flags=re.IGNORECASE)[0].strip()
        if lead_part and len(lead_part) > 2:
            aid = re.sub(r'[^a-zA-Z0-9_\-]', '-', lead_part.lower()).strip('-')[:40]
            if not any(a["id"] == aid for a in agents):
                agents.append(
                    {
                        "id": aid,
                        "role": f"Crew Coordinator: {lead_part}",
                        "kind": "agent",
                        "tools": [],
                        "source": "crew_manifest_declaration",
                        "evidence": "DETECTED",
                    }
                )

    # 2. Sub-Agents list (e.g. Agents: Researcher (LLM: gpt-4.1), Author (LLM: gpt-4.1), and Editor (LLM: gpt-4.1))
    agents_match = re.search(
        r'(?:<strong>)?(?:Agents?|Sub-Agents?|Worker Agents?)(?:</strong>)?\s*:\s*([^<\n\r]+)',
        decoded_source,
        re.IGNORECASE,
    )
    if agents_match:
        raw_list = agents_match.group(1).strip()
        parts = re.split(r',\s*and\s+|,\s*|\s+and\s+', raw_list)
        for part in parts:
            cleaned = part.strip().rstrip('.')
            if cleaned and len(cleaned) > 2 and not cleaned.lower().startswith(('etc', 'none', 'and')):
                aid = re.sub(r'[^a-zA-Z0-9_\-]', '-', cleaned.lower()).strip('-')[:40]
                if not any(a["id"] == aid for a in agents):
                    agents.append(
                        {
                            "id": aid,
                            "role": f"Autonomous Sub-Agent: {cleaned}",
                            "kind": "agent",
                            "tools": [],
                            "source": "crew_agents_declaration",
                            "evidence": "DETECTED",
                        }
                    )

    # 3. Declared Tools list (e.g. Tools: Search and Scrape)
    tools_match = re.search(
        r'(?:<strong>)?(?:Tools?|Declared Tools?|Callable Tools?)(?:</strong>)?\s*:\s*([^<\n\r]+)',
        decoded_source,
        re.IGNORECASE,
    )
    if tools_match:
        raw_tools = tools_match.group(1).strip()
        t_parts = re.split(r',\s*and\s+|,\s*|\s+and\s+', raw_tools)
        for t in t_parts:
            c_tool = t.strip().rstrip('.')
            if c_tool and len(c_tool) > 1 and not c_tool.lower().startswith(('etc', 'none', 'and')):
                t_name = re.sub(r'[^a-zA-Z0-9_]', '_', c_tool.lower()).strip('_')[:40]
                if not any(tool["name"] == t_name for tool in tools):
                    tools.append(
                        {
                            "name": t_name,
                            "kind": "tool",
                            "method": "POST" if any(w in t_name for w in ("write", "scrape", "mutate", "post", "send")) else "GET",
                            "method_evidence": "INFERRED",
                            "path": f"/tools/{t_name}",
                            "risk": f"Declared Tool Surface: {c_tool} (method/path inferred from manifest)",
                            "evidence": "DETECTED",
                        }
                    )

    # --- C2. Framework & Code Signatures (Spring AI, LangChain4j, A2A) ---
    agent_sdk_patterns = [
        (r"/\.well-known/agent\.json", "a2a-manifest-agent", "A2A Protocol Agent Card (/.well-known/agent.json)", "DETECTED"),
        (r"\b(?:SpringAI|ChatClient\.Builder|@McpServer)\b", "spring-ai-agent", "Java Spring AI ChatClient / MCP Agent", "DETECTED"),
        (r"\b(?:LangChain4j|AiServices\.create|McpToolProvider)\b", "langchain4j-agent", "Java LangChain4j Declarative AI Service Agent", "DETECTED"),
    ]
    # Only append generic framework fallback if no specific agents have been extracted yet
    if not agents:
        agent_sdk_patterns.append(
            (r"\b(?:LangGraph|CrewAI|AutoGen|MCPClient|AgentSwarm)\b", "python-js-agent-runtime", "Autonomous Agent Framework Keyword Match (LangGraph/CrewAI/AutoGen)", "INFERRED")
        )
    for pattern, aid, role, ev_kind in agent_sdk_patterns:
        if re.search(pattern, combined_source, re.IGNORECASE) and not any(a["id"] == aid for a in agents):
            agents.append(
                {
                    "id": aid,
                    "role": role,
                    "kind": "agent",
                    "tools": [],
                    "source": "code_signature",
                    "evidence": ev_kind,
                }
            )

    # --- D. Identify Real Callable Tools (HTML/JSP/JSF Forms, Spring/REST/GraphQL/MCP/Java .do/.action Routes) ---
    for idx, form_match in enumerate(re.finditer(r"<form\b([^>]*)>", html_body, re.IGNORECASE)):
        attrs = form_match.group(1)
        action_m = re.search(r'(?:action|th:action)=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        method_m = re.search(r'method=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        action_path = (action_m.group(1).strip() if action_m else f"/form-submit-{idx + 1}")[:65]
        method = (method_m.group(1).strip().upper() if method_m else "POST")
        is_java_form = any(ext in action_path.lower() for ext in (".jsp", ".do", ".action", ".xhtml", ".jsf")) or (
            "ViewState" in html_body
        )
        tools.append(
            {
                "name": f"java_form_{idx + 1}" if is_java_form else f"html_form_{idx + 1}",
                "kind": "tool",
                "method": method,
                "method_evidence": "DETECTED" if method_m else "INFERRED",
                "path": action_path,
                "risk": "Java JSP/JSF Form Action Surface" if is_java_form else "HTML Form Action Surface",
                "evidence": "DETECTED" if action_m else "INFERRED",
            }
        )

    api_route_matches = re.findall(
        r'["\'](/(?:api|v1|v2|v3|tools|graphql|mcp|sse|actuator|orders|inventory|settlement)[a-zA-Z0-9_\-/.]{0,55})["\']',
        combined_source,
    )
    java_action_matches = re.findall(
        r'["\'](/[a-zA-Z0-9_\-/]{1,45}\.(?:jsp|jspx|do|action|xhtml|jsf))["\']',
        combined_source,
    )
    seen_paths = {t["path"] for t in tools}
    for api_path in api_route_matches + java_action_matches:
        if api_path not in seen_paths and not api_path.endswith((".js", ".css", ".png", ".svg", ".ico", ".woff2")):
            seen_paths.add(api_path)
            lower_p = api_path.lower()
            method = (
                "DELETE"
                if any(w in lower_p for w in ("purge", "delete", "remove"))
                else (
                    "POST"
                    if any(w in lower_p for w in ("mutate", "write", "create", "update", "refund", "pay", "reserve", "message", ".do", ".action"))
                    else "GET"
                )
            )
            tools.append(
                {
                    "name": api_path.strip("/").replace("/", "_").replace(".", "_"),
                    "kind": "tool",
                    "method": method,
                    "method_evidence": "INFERRED",
                    "path": api_path,
                    "risk": "Java / Spring / MCP Endpoint" if any(k in lower_p for k in (".jsp", ".do", ".action", "actuator", "mcp")) else "Discovered API Tool Endpoint",
                    "evidence": "DETECTED",
                }
            )
        if len(tools) >= 10:
            break

    return {
        "agents": agents,
        "tools": tools,
        "detected_stacks": detected_stacks,
        "java_extensions": java_extensions,
        "jss_and_ui_libs": jss_and_ui_libs,
        "has_java_stack": len(java_extensions) > 0,
        "has_jss_or_spa": len(jss_and_ui_libs) > 0,
    }


def _classify_external_agents_and_tools(
    html_body: str,
    headers_dict: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Backwards-compatible helper returning (agents, tools) from multi-stack detector."""
    res = detect_multi_stack_and_surfaces(html_body, headers_dict)
    return res["agents"], res["tools"]


def _fmt_ms(val: Any) -> str:
    return f"{val}ms" if val is not None else "not measured"


def _fmt_num(val: Any, suffix: str = "") -> str:
    return f"{val}{suffix}" if val is not None else "not measured"


def build_four_pillar_evaluation(
    recon: dict[str, Any],
    run_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the 4-Pillar Evaluation & Benchmark Scorecard grounded in the 4 reference guides.

    Truthfulness rules (B1):
    - Never substitute silent numeric defaults (no 4.2ms, 52, 142ms, 8, 3, 44, 0.333).
    - If a metric is unmeasured (None), render 'not measured' and status 'UNKNOWN'.
    - A benchmark row may only be 'PROTECTED' if a real gateway run measured that row's metric.
    """
    is_builtin = bool(recon.get("is_builtin", False))
    has_agents = bool(recon.get("has_active_agents", False))
    status_code = int(recon.get("status_code", 200))
    agents = recon.get("agents_detected", [])
    tools = recon.get("tools_detected", [])
    tech_stack = recon.get("tech_stack") or ["HTML5 / Standard HTTP"]

    raw_lat = recon.get("latency_profile") or {}
    lat_prof = {
        "cold_total_ms": raw_lat.get("cold_total_ms", recon.get("latency_ms")),
        "ttfb_ms": raw_lat.get("ttfb_ms"),
        "download_ms": raw_lat.get("download_ms"),
        "warm_p50_ms": raw_lat.get("warm_p50_ms"),
        "burst_3x_p95_ms": raw_lat.get("burst_3x_p95_ms"),
        "degradation_ratio": raw_lat.get("degradation_ratio"),
        "latency_cause": raw_lat.get("latency_cause") or "not measured",
    }
    sec_hdrs = recon.get("security_headers") or {}

    has_gateway_run = bool(run_result and run_result.get("gateway") and run_result.get("direct"))
    d = (run_result or {}).get("direct") or {}
    g = (run_result or {}).get("gateway") or {}

    # Check whether each row actually has real measured data from the gateway run
    row1_measured_gw = bool(
        has_gateway_run and is_builtin and d.get("upstream_errors") is not None and g.get("upstream_errors") is not None
    )
    row2_measured_gw = bool(has_gateway_run and is_builtin and g.get("client_calls") is not None)
    row3_measured_gw = bool(
        has_gateway_run and is_builtin and g.get("cas_version") is not None and d.get("lost_updates") is not None
    )
    row4_measured_gw = bool(
        has_gateway_run and is_builtin and g.get("policy_denied") is not None and g.get("approval_pending") is not None
    )
    row5_measured_gw = bool(
        has_gateway_run and is_builtin and g.get("depth_denied") is not None and g.get("calls_avoided") is not None
    )
    row6_measured_gw = bool(has_gateway_run and is_builtin and g.get("client_calls") is not None)
    row7_measured_gw = bool(
        has_gateway_run and is_builtin and d.get("success_rate") is not None and g.get("cas_version") is not None
    )

    # Row 1: Latency & Burst Tail
    d_p99 = (d.get("latency_ms") or {}).get("p99") if isinstance(d.get("latency_ms"), dict) else None
    g_p50 = (g.get("latency_ms") or {}).get("p50") if isinstance(g.get("latency_ms"), dict) else None
    if row1_measured_gw:
        r1_current = (
            f"MEASURED: Exposed {d.get('upstream_errors')}× 429s (p99 {_fmt_ms(d_p99)}) → "
            f"Gateway {g.get('upstream_errors')} errors (p50 {_fmt_ms(g_p50)})"
        )
        r1_lacking = f"Raw burst triggered {d.get('upstream_errors')}× HTTP 429s and tail-latency spike ({_fmt_ms(d_p99)} p99)"
        r1_status = "PROTECTED"
        r1_ev = "MEASURED"
    elif status_code == 0 or lat_prof["ttfb_ms"] is None:
        r1_current = f"not measured ({lat_prof['latency_cause']})"
        r1_lacking = "Latency not measured (no live probe or benchmark run yet)"
        r1_status = "UNKNOWN"
        r1_ev = "UNKNOWN"
    else:
        r1_current = (
            f"MEASURED: Cold {_fmt_ms(lat_prof['cold_total_ms'])} · TTFB {_fmt_ms(lat_prof['ttfb_ms'])} · "
            f"Warm p50 {_fmt_ms(lat_prof['warm_p50_ms'])} · 3× Burst p95 {_fmt_ms(lat_prof['burst_3x_p95_ms'])} "
            f"({_fmt_num(lat_prof['degradation_ratio'], '×')} ratio — {lat_prof['latency_cause']})"
        )
        r1_lacking = (
            f"Burst p95 degrades {lat_prof['degradation_ratio']}× ({_fmt_ms(lat_prof['burst_3x_p95_ms'])}) under concurrent load without admission queueing"
            if (lat_prof["degradation_ratio"] is not None and lat_prof["degradation_ratio"] > 1.3)
            else "No adaptive concurrency queue or singleflight coalescing in front of origin"
        )
        r1_status = "PASS" if lat_prof["ttfb_ms"] <= 250 else "WARN"
        r1_ev = "MEASURED"

    # Row 2: OpenTelemetry Trace Correlation
    if row2_measured_gw:
        r2_current = "MEASURED: call_id + parent_call_id + goal_id + SSE event stream"
        r2_status = "PROTECTED"
        r2_ev = "MEASURED"
    elif status_code == 0:
        r2_current = "not measured (origin unreachable)"
        r2_status = "UNKNOWN"
        r2_ev = "UNKNOWN"
    else:
        r2_current = f"DETECTED: traceparent={sec_hdrs.get('has_traceparent', False)} · x-request-id={sec_hdrs.get('has_request_id', False)}"
        r2_status = "PASS" if (sec_hdrs.get("has_traceparent") or sec_hdrs.get("has_request_id")) else "LACKING"
        r2_ev = "DETECTED"

    # Row 3: Idempotency & Optimistic Concurrency (CAS / ETag)
    if row3_measured_gw:
        r3_current = (
            f"MEASURED: Fenced lease tokens + CAS v{_fmt_num(g.get('cas_version'))} "
            f"({_fmt_num(g.get('lost_updates'))} lost writes vs {_fmt_num(d.get('lost_updates'))} raw lost)"
        )
        r3_lacking = f"Unfenced concurrent POST writes suffered {_fmt_num(d.get('lost_updates'))} lost updates on shared state"
        r3_status = "PROTECTED"
        r3_ev = "MEASURED"
    elif status_code == 0:
        r3_current = "not measured (origin unreachable)"
        r3_lacking = "Origin unreachable; ETag / Idempotency headers not measured"
        r3_status = "UNKNOWN"
        r3_ev = "UNKNOWN"
    else:
        r3_current = f"DETECTED: ETag={sec_hdrs.get('has_etag', False)} · Idempotency-Key={sec_hdrs.get('has_idempotency', False)}"
        r3_lacking = (
            f"{len(tools)} callable tool surface(s) lack If-Match CAS versioning and monotonic fencing tokens"
            if len(tools) > 0
            else "State-mutating routes lack optimistic concurrency (ETag / If-Match) verification"
        )
        r3_status = "PASS" if sec_hdrs.get("has_etag") else "LACKING"
        r3_ev = "DETECTED"

    # Row 4: Lethal Trifecta Defense
    if row4_measured_gw:
        r4_current = (
            f"MEASURED: Trifecta broken in code: {_fmt_num(g.get('policy_denied'))} destructive DELETE blocked + "
            f"{_fmt_num(g.get('approval_pending'))} high-value action paused"
        )
        r4_lacking = "Untrusted prompt context had direct, unmediated access to destructive DELETE and high-value tools"
        r4_status = "PROTECTED"
        r4_ev = "MEASURED"
    elif status_code == 0:
        r4_current = "not measured (origin unreachable)"
        r4_lacking = "Origin unreachable; policy surface not inspected"
        r4_status = "UNKNOWN"
        r4_ev = "UNKNOWN"
    else:
        r4_current = f"DETECTED: {len(agents)} agent(s) × {len(tools)} tool(s) · CSP={sec_hdrs.get('has_csp', False)}"
        r4_lacking = (
            f"{len(agents)} declared agent(s) have unmediated access to {len(tools)} tool(s) without policy authorization"
            if has_agents and len(tools) > 0
            else "No external policy enforcement layer between AI/client callers and backend tool endpoints"
        )
        r4_status = "PASS" if (not has_agents and len(tools) == 0) else "LACKING"
        r4_ev = "DETECTED"

    # Row 5: OWASP LLM06 Unbounded Consumption & ASI08 Cascading Failures
    if row5_measured_gw:
        r5_current = (
            f"MEASURED: Depth capped at d={_fmt_num(g.get('depth_limit'))} "
            f"({_fmt_num(g.get('depth_denied'))} runaway calls pruned) · {_fmt_num(g.get('calls_avoided'))} backend calls saved"
        )
        r5_lacking = f"Runaway 2^d sub-agent fan-out reached depth d={_fmt_num(d.get('depth_reached'))} and flooded backend with duplicate calls"
        r5_status = "PROTECTED"
        r5_ev = "MEASURED"
    elif status_code == 0:
        r5_current = "not measured (origin unreachable)"
        r5_lacking = "Origin unreachable; rate-limit headers not inspected"
        r5_status = "UNKNOWN"
        r5_ev = "UNKNOWN"
    else:
        r5_current = f"DETECTED: RateLimit headers={sec_hdrs.get('has_ratelimit', False)} · Retry-After={sec_hdrs.get('has_retry_after', False)}"
        r5_lacking = "Origin HTTP headers lack RateLimit-Limit / Quota budgets to stop Denial-of-Wallet or agent retry storms"
        r5_status = "PASS" if sec_hdrs.get("has_ratelimit") else "LACKING"
        r5_ev = "DETECTED"

    # Row 6: Pillar 3 Multi-Stack, Agent & Tool Discovery
    if status_code == 0:
        r6_current = "not measured (origin unreachable)"
        r6_status = "UNKNOWN"
        r6_ev = "UNKNOWN"
    elif row6_measured_gw:
        r6_current = f"MEASURED: Stacks: {', '.join(tech_stack)} · {len(agents)} Agent(s) · {len(tools)} Tool(s)"
        r6_status = "PROTECTED"
        r6_ev = "MEASURED"
    elif has_agents or len(tools) > 0:
        r6_current = f"DETECTED: Stacks: {', '.join(tech_stack)} · {len(agents)} Agent(s) · {len(tools)} Tool(s)"
        r6_status = "DETECTED"
        r6_ev = "DETECTED"
    else:
        r6_current = f"NOT_DETECTED_STATICALLY: Stacks: {', '.join(tech_stack)} · 0 Agents · 0 Tools in static HTML/JS"
        r6_status = "NOT_DETECTED_STATICALLY"
        r6_ev = "NOT_DETECTED_STATICALLY"

    # Row 7: Pillar 4 Repeat-Trial Reliability (pass^k) & Outcome State Assertion
    if row7_measured_gw:
        d_sr_pct = round(float(d["success_rate"]) * 100, 1)
        r7_current = f"MEASURED: Exposed {d_sr_pct}% → Gateway 100.0% valid completion · State v{_fmt_num(g.get('cas_version'))} measured"
        r7_lacking = f"Exposed swarm pass^k collapses ({d_sr_pct}% completion, {_fmt_num(d.get('lost_updates'))} corrupted state writes)"
        r7_status = "PROTECTED"
        r7_ev = "MEASURED"
    elif status_code == 0:
        r7_current = "not measured (origin unreachable)"
        r7_lacking = "Origin unreachable; repeat-trial reliability not measured"
        r7_status = "UNKNOWN"
        r7_ev = "UNKNOWN"
    elif not has_agents:
        r7_current = "NOT_DETECTED_STATICALLY: 0 active agents detected in static scan — pass^k not applicable"
        r7_lacking = "No automated L3/L5 agent stress harness or deterministic seed benchmark attached to endpoint"
        r7_status = "NOT_DETECTED_STATICALLY"
        r7_ev = "NOT_DETECTED_STATICALLY"
    else:
        r7_current = f"DETECTED: {len(agents)} declared autonomous agent(s) (pass^k not measured — run audit on owned target)"
        r7_lacking = f"No automated pass^k or state assertion harness attached to declared agent(s) ({', '.join(a['id'] for a in agents[:2])})"
        r7_status = "WARN"
        r7_ev = "DETECTED"

    spec_map = {s.row_id: s for s in SCORECARD_SPECS}

    s1 = spec_map["latency_burst_tail"]
    s2 = spec_map["opentelemetry_correlation"]
    s3 = spec_map["idempotency_concurrency"]
    s4 = spec_map["lethal_trifecta_defense"]
    s5 = spec_map["unbounded_consumption_cascades"]
    s6 = spec_map["multi_stack_discovery"]
    s7 = spec_map["repeat_trial_reliability"]

    benchmarks: list[dict[str, Any]] = [
        {
            "row_id": s1.row_id,
            "pillar": s1.pillar,
            "dimension": s1.dimension,
            "standard_ref": s1.threshold_source,
            "threshold_source": s1.threshold_source,
            "rule_description": s1.rule_description,
            "thresholds": s1.thresholds,
            "measured_current": r1_current,
            "what_it_was_lacking": r1_lacking,
            "what_it_has_to_be": "TTFB ≤ 250ms · Burst p95 ≤ 1.8× Warm p50 · 0 HTTP 429s via Adaptive Admission + Singleflight",
            "status": r1_status,
            "evidence_kind": r1_ev,
            "gateway_module": s1.gateway_module,
        },
        {
            "row_id": s2.row_id,
            "pillar": s2.pillar,
            "dimension": s2.dimension,
            "standard_ref": s2.threshold_source,
            "threshold_source": s2.threshold_source,
            "rule_description": s2.rule_description,
            "thresholds": s2.thresholds,
            "measured_current": r2_current,
            "what_it_was_lacking": "Missing W3C traceparent / gen_ai.* span attributes & parent→child sub-agent call lineage",
            "what_it_has_to_be": "100% requests carry request_id/trace_id + parent_call_id span tree + token/cost attribution",
            "status": r2_status,
            "evidence_kind": r2_ev,
            "gateway_module": s2.gateway_module,
        },
        {
            "row_id": s3.row_id,
            "pillar": s3.pillar,
            "dimension": s3.dimension,
            "standard_ref": s3.threshold_source,
            "threshold_source": s3.threshold_source,
            "rule_description": s3.rule_description,
            "thresholds": s3.thresholds,
            "measured_current": r3_current,
            "what_it_was_lacking": r3_lacking,
            "what_it_has_to_be": "Monotonic fencing_token leases + If-Match: <version> CAS check returning 409 on stale writes (0 lost updates)",
            "status": r3_status,
            "evidence_kind": r3_ev,
            "gateway_module": s3.gateway_module,
        },
        {
            "row_id": s4.row_id,
            "pillar": s4.pillar,
            "dimension": s4.dimension,
            "standard_ref": s4.threshold_source,
            "threshold_source": s4.threshold_source,
            "rule_description": s4.rule_description,
            "thresholds": s4.thresholds,
            "measured_current": r4_current,
            "what_it_was_lacking": r4_lacking,
            "what_it_has_to_be": "Enforce authorization outside the LLM: YAML tool allow-lists + read_only_agent rules + Human Approval Gate",
            "status": r4_status,
            "evidence_kind": r4_ev,
            "gateway_module": s4.gateway_module,
        },
        {
            "row_id": s5.row_id,
            "pillar": s5.pillar,
            "dimension": s5.dimension,
            "standard_ref": s5.threshold_source,
            "threshold_source": s5.threshold_source,
            "rule_description": s5.rule_description,
            "thresholds": s5.thresholds,
            "measured_current": r5_current,
            "what_it_was_lacking": r5_lacking,
            "what_it_has_to_be": "Hard per-goal max_calls, max_depth=3 lineage breaker, weighted fair queue, and Retry-After budgets",
            "status": r5_status,
            "evidence_kind": r5_ev,
            "gateway_module": s5.gateway_module,
        },
        {
            "row_id": s6.row_id,
            "pillar": s6.pillar,
            "dimension": s6.dimension,
            "standard_ref": s6.threshold_source,
            "threshold_source": s6.threshold_source,
            "rule_description": s6.rule_description,
            "thresholds": s6.thresholds,
            "measured_current": r6_current,
            "what_it_was_lacking": (
                "Plain HTML-only scanners miss Java (Spring Boot/AI, LangChain4j, JSP/JSF/Vaadin) and JSS/React client bundles"
            ),
            "what_it_has_to_be": "Full-stack inspection across HTML, Java (.jsp/.do/ViewState/Actuator/Spring AI), JSS (makeStyles/MUI), JS bundles & MCP/A2A",
            "status": r6_status,
            "evidence_kind": r6_ev,
            "gateway_module": s6.gateway_module,
        },
        {
            "row_id": s7.row_id,
            "pillar": s7.pillar,
            "dimension": s7.dimension,
            "standard_ref": s7.threshold_source,
            "threshold_source": s7.threshold_source,
            "rule_description": s7.rule_description,
            "thresholds": s7.thresholds,
            "measured_current": r7_current,
            "what_it_was_lacking": r7_lacking,
            "what_it_has_to_be": "pass^k ≥ 99% on valid tool calls · Environment state assertion (0 lost updates) · Deterministic seeded eval gate",
            "status": r7_status,
            "evidence_kind": r7_ev,
            "gateway_module": s7.gateway_module,
        },
    ]

    evidence_kinds = [b["evidence_kind"] for b in benchmarks]
    statuses = [b["status"] for b in benchmarks]

    confidence = compute_evidence_confidence(evidence_kinds)
    site_posture = evaluate_site_posture(statuses, evidence_kinds)
    gateway_effect = evaluate_gateway_effect(has_gateway_run, statuses, d, g)

    # Compute overall readiness score via calculations.py (NumPy-powered, LLM-free)
    pillar_result = four_pillar_score(
        statuses,
        has_gateway_run=has_gateway_run,
    )
    total_score = pillar_result["score"]
    grade = pillar_result["grade"]

    return {
        "overall_score": total_score,
        "grade": grade,
        "confidence": confidence,
        "site_posture": site_posture,
        "gateway_effect": gateway_effect,
        "tech_stack": tech_stack,
        "latency_profile": lat_prof,
        "agents_count": len(agents),
        "tools_count": len(tools),
        "has_active_agents": has_agents,
        "benchmarks": benchmarks,
    }


async def perform_url_recon(url: str, base_host: str = "http://127.0.0.1:8010") -> dict[str, Any]:
    """Perform truthful reconnaissance & 4-Pillar Evaluation on a target URL (HTML, Java/Spring/JSP, JSS, SPA)."""
    raw = (url or "").strip()
    if not raw:
        raw = f"{base_host}/targets/aegis-store"
    elif raw.startswith("/"):
        raw = f"{base_host}{raw}"
    elif not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"

    parsed = urlparse(raw)

    # Check if this is one of our built-in multi-agent target applications
    for item in BUILT_IN_TARGETS.values():
        if item["path"] in raw or item["slug"] in raw:
            lat_prof: dict[str, Any] = {
                "cold_total_ms": None,
                "ttfb_ms": None,
                "download_ms": None,
                "warm_p50_ms": None,
                "burst_3x_p95_ms": None,
                "degradation_ratio": None,
                "latency_cause": "not measured (run audit to measure)",
            }
            labeled_agents = [{**a, "evidence": "DETECTED"} for a in item["agents"]]
            labeled_tools = [{**e, "evidence": "DETECTED", "method_evidence": "DETECTED"} for e in item["endpoints"]]
            base_recon: dict[str, Any] = {
                "url": raw,
                "slug": item["slug"],
                "render_url": item["path"],
                "is_builtin": True,
                "has_active_agents": True,
                "project_id": item["project_id"],
                "title": item["title"],
                "domain": item["domain"],
                "category": item["category"],
                "tech_stack": item.get("tech_stack", ["HTML5", "FastAPI", "JSS"]),
                "status_code": 200,
                "latency_ms": None,
                "latency_profile": lat_prof,
                "security_headers": {
                    "has_csp": False,
                    "has_xfo": False,
                    "has_ratelimit": False,
                    "has_retry_after": False,
                    "has_etag": False,
                    "has_idempotency": False,
                    "has_traceparent": False,
                    "has_request_id": False,
                },
                "frame_blocked": False,
                "proxy_mode": "direct_interactive_target",
                "forms_detected": 3,
                "interactive_elements": 6,
                "agents_detected": labeled_agents,
                "tools_detected": labeled_tools,
                "endpoints": labeled_tools,
                "vulnerabilities_without_gateway": [
                    "DETECTED: No singleflight deduplication on burst GET endpoints (vulnerable to 429 cascade)",
                    "DETECTED: Unfenced concurrent POST state mutations (vulnerable to lost updates)",
                    "DETECTED: Unbounded sub-agent recursion depth on graph/trace endpoints",
                    "DETECTED: Missing human-in-the-loop approval gate on high-value POST actions",
                ],
            }
            base_recon["evaluation_report"] = build_four_pillar_evaluation(base_recon)
            return base_recon

    # External URL: perform real HTTP reconnaissance + multi-sample latency profiling + JS bundle inspection
    status_code = 0
    headers_dict: dict[str, str] = {}
    html_body = ""
    script_bodies: list[str] = []
    error_note: str | None = None

    cold_total_ms: float | None = None
    ttfb_ms: float | None = None
    download_ms: float | None = None
    warm_p50_ms: float | None = None
    burst_3x_p95_ms: float | None = None
    degradation_ratio: float | None = None
    probe_waves: list[dict[str, Any]] = []
    probes_sent = 0
    probes_succeeded = 0
    probes_errors = 0

    try:
        allow_local_env = bool(os.getenv("AGENT_GATEWAY_ALLOW_LOCAL_TESTING"))
        raw = validate_url_for_recon(raw, allow_local=allow_local_env)
    except ValueError as val_err:
        error_note = str(val_err)
        probes_errors += 1

    try:
        if error_note:
            raise ValueError(error_note)

        async with httpx.AsyncClient(
            timeout=6.0,
            follow_redirects=True,
            headers={"User-Agent": "ZifiBrowser/1.0 (+AgentGateway-Security-Recon)"},
        ) as client:
            # Stage 1: Cold request (streaming to separate TTFB vs body download)
            probes_sent += 1
            t0 = time.perf_counter()
            async with client.stream("GET", raw) as stream_resp:
                status_code = stream_resp.status_code
                headers_dict = {k.lower(): v for k, v in stream_resp.headers.items()}
                ttfb_ms = round((time.perf_counter() - t0) * 1000, 1)
                chunks: list[bytes] = []
                total_bytes = 0
                async for chunk in stream_resp.aiter_bytes():
                    chunks.append(chunk)
                    total_bytes += len(chunk)
                    if total_bytes >= 80_000:
                        break
                raw_bytes = b"".join(chunks)
                html_body = raw_bytes.decode("utf-8", errors="replace")
            cold_total_ms = round((time.perf_counter() - t0) * 1000, 1)
            download_ms = round(max(0.1, cold_total_ms - ttfb_ms), 1)
            if 200 <= status_code < 400:
                probes_succeeded += 1
            else:
                probes_errors += 1

            probe_waves.append(
                {
                    "seq": len(probe_waves) + 1,
                    "wave": len(probe_waves) + 1,
                    "agent_id": "zifi-recon-probe",
                    "method": "GET",
                    "endpoint": parsed.path or "/",
                    "exposed_status": f"{status_code} (TTFB {ttfb_ms}ms · Total {cold_total_ms}ms)",
                    "gateway_status": None,
                    "gateway_action": "RECON_ONLY_NO_GATEWAY",
                    "latency_ms": cold_total_ms,
                    "evidence_kind": "MEASURED",
                }
            )

            # Stage 2: Warm keep-alive + 3x concurrent burst probe (fast timeout)
            try:
                probes_sent += 1
                t_warm = time.perf_counter()
                w_resp = await client.head(raw, timeout=2.5)
                warm_p50_ms = round((time.perf_counter() - t_warm) * 1000, 1)
                if 200 <= w_resp.status_code < 400:
                    probes_succeeded += 1
                else:
                    probes_errors += 1

                probe_waves.append(
                    {
                        "seq": len(probe_waves) + 1,
                        "wave": len(probe_waves) + 1,
                        "agent_id": "zifi-recon-probe",
                        "method": "HEAD",
                        "endpoint": parsed.path or "/",
                        "exposed_status": f"{w_resp.status_code} (Warm p50 {warm_p50_ms}ms)",
                        "gateway_status": None,
                        "gateway_action": "RECON_ONLY_NO_GATEWAY",
                        "latency_ms": warm_p50_ms,
                        "evidence_kind": "MEASURED",
                    }
                )

                async def _one_burst() -> tuple[int, float]:
                    tb = time.perf_counter()
                    b_resp = await client.head(raw, timeout=2.5)
                    return b_resp.status_code, round((time.perf_counter() - tb) * 1000, 1)

                probes_sent += 3
                burst_samples = await asyncio.gather(
                    _one_burst(), _one_burst(), _one_burst(), return_exceptions=True
                )
                valid_burst: list[float] = []
                for sample in burst_samples:
                    if isinstance(sample, tuple):
                        b_code, b_ms = sample
                        valid_burst.append(b_ms)
                        if 200 <= b_code < 400:
                            probes_succeeded += 1
                        else:
                            probes_errors += 1
                    else:
                        probes_errors += 1

                if valid_burst:
                    burst_3x_p95_ms = round(max(valid_burst), 1)
                    probe_waves.append(
                        {
                            "seq": len(probe_waves) + 1,
                            "wave": len(probe_waves) + 1,
                            "agent_id": "zifi-recon-probe (3x)",
                            "method": "HEAD",
                            "endpoint": f"{parsed.path or '/'}?burst=3",
                            "exposed_status": f"{len(valid_burst)}/3 completed (3× Burst p95 {burst_3x_p95_ms}ms)",
                            "gateway_status": None,
                            "gateway_action": "RECON_ONLY_NO_GATEWAY",
                            "latency_ms": burst_3x_p95_ms,
                            "evidence_kind": "MEASURED",
                        }
                    )
            except Exception:
                # Never fabricate warm_p50_ms or burst_3x_p95_ms from multipliers
                pass

            # Stage 3: Inspect up to 2 linked JS bundles (for JSS / React / Angular / Vaadin / GWT SPA discovery)
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html_body, re.IGNORECASE)
            for src in script_srcs[:2]:
                full_script_url = urljoin(raw, src)
                try:
                    s_resp = await client.get(full_script_url, timeout=1.5)
                    if s_resp.status_code == 200:
                        script_bodies.append(s_resp.text[:35_000])
                except Exception:
                    pass

            # Stage 4: robots.txt reconnaissance (check Disallow rules)
            robots_disallow = False
            try:
                robots_url = urljoin(raw, "/robots.txt")
                r_resp = await client.get(robots_url, timeout=1.5)
                if r_resp.status_code == 200:
                    for line in r_resp.text.splitlines():
                        if line.strip().lower().startswith("disallow:"):
                            dis_val = line.split(":", 1)[1].strip()
                            if dis_val in ("/", "/*") or (dis_val and parsed.path.startswith(dis_val)):
                                robots_disallow = True
                                break
            except Exception:
                pass
    except httpx.TooManyRedirects as exc:
        error_note = f"TooManyRedirects: redirect loop detected ({exc})"
        status_code = 302
        probes_errors += 1
        cold_total_ms = None
        ttfb_ms = None
        download_ms = None
        warm_p50_ms = None
        burst_3x_p95_ms = None
        degradation_ratio = None
    except Exception as exc:
        error_note = f"{type(exc).__name__}: origin unreachable ({exc})"
        status_code = 0
        probes_errors += 1
        cold_total_ms = None
        ttfb_ms = None
        download_ms = None
        warm_p50_ms = None
        burst_3x_p95_ms = None
        degradation_ratio = None

    latency_ms = cold_total_ms
    if status_code == 0 or cold_total_ms is None or ttfb_ms is None or download_ms is None:
        degradation_ratio = None
        latency_cause = "not measured (origin unreachable)"
    elif warm_p50_ms is not None and burst_3x_p95_ms is not None:
        _lat_summary = latency_waterfall_summary(cold_total_ms, ttfb_ms, download_ms, warm_p50_ms, burst_3x_p95_ms)
        degradation_ratio = _lat_summary["degradation_ratio"]  # type: ignore[assignment]
        latency_cause = str(_lat_summary["latency_cause"])
    else:
        degradation_ratio = None
        latency_cause = f"Cold GET measured ({cold_total_ms}ms); warm/burst probes not measured"

    latency_profile = {
        "cold_total_ms": cold_total_ms,
        "ttfb_ms": ttfb_ms,
        "download_ms": download_ms,
        "warm_p50_ms": warm_p50_ms,
        "burst_3x_p95_ms": burst_3x_p95_ms,
        "degradation_ratio": degradation_ratio,
        "latency_cause": latency_cause,
    }

    xfo = headers_dict.get("x-frame-options", "")
    csp = headers_dict.get("content-security-policy", "")
    frame_blocked = bool(xfo) or ("frame-ancestors" in csp.lower())

    security_headers = {
        "has_csp": bool(csp),
        "has_xfo": bool(xfo),
        "has_ratelimit": any("ratelimit" in k or "rate-limit" in k for k in headers_dict),
        "has_retry_after": "retry-after" in headers_dict,
        "has_etag": "etag" in headers_dict,
        "has_idempotency": any("idempotency" in k for k in headers_dict),
        "has_traceparent": "traceparent" in headers_dict or "x-trace-id" in headers_dict,
        "has_request_id": "x-request-id" in headers_dict or "x-correlation-id" in headers_dict,
    }

    title_match = re.search(r"<title[^>]*>(.*?)</title>", html_body, re.IGNORECASE | re.DOTALL)
    page_title = (
        html.unescape(title_match.group(1).strip())[:90]
        if title_match
        else f"{parsed.netloc or raw}"
    )
    forms_count = len(re.findall(r"<form\b", html_body, re.IGNORECASE))
    buttons_count = len(re.findall(r"<(button|input|a)\b", html_body, re.IGNORECASE))

    content_type = headers_dict.get("content-type", "").lower()
    is_binary = any(t in content_type for t in ("application/pdf", "image/", "video/", "audio/", "application/octet-stream"))

    if is_binary:
        tech_stack = [f"Binary Content ({content_type.split(';')[0]})"]
        stack_analysis = {
            "agents": [],
            "tools": [],
            "detected_stacks": tech_stack,
            "java_extensions": [],
            "jss_and_ui_libs": [],
            "has_java_stack": False,
            "has_jss_or_spa": False,
        }
        agents_detected = []
        tools_detected = []
        has_active_agents = False
    else:
        stack_analysis = detect_multi_stack_and_surfaces(html_body, headers_dict, script_bodies)
        agents_detected = stack_analysis["agents"]
        tools_detected = stack_analysis["tools"]
        tech_stack = stack_analysis["detected_stacks"]
        has_active_agents = len(agents_detected) > 0

    vulnerabilities: list[str] = []
    if not has_active_agents and len(tools_detected) == 0:
        vulnerabilities.append(
            f"NOT_DETECTED_STATICALLY ({', '.join(tech_stack)}): 0 autonomous agents and 0 callable tool endpoints detected in static HTML/JS."
        )
    else:
        if has_active_agents:
            vulnerabilities.append(
                f"DETECTED: {len(agents_detected)} agent declaration(s) without Agent Gateway admission/budget headers."
            )
        if len(tools_detected) > 0:
            vulnerabilities.append(
                f"DETECTED: {len(tools_detected)} callable tool/form surface(s) without fencing tokens or idempotency keys."
            )
    if not security_headers["has_ratelimit"]:
        vulnerabilities.append(
            "DETECTED (OWASP LLM06 / ASI08): Missing RateLimit-Limit / Retry-After headers for burst traffic protection."
        )

    ext_recon: dict[str, Any] = {
        "url": raw,
        "slug": "external-target",
        "render_url": f"/api/zifi/proxy?url={raw}",
        "is_builtin": False,
        "has_active_agents": has_active_agents,
        "project_id": "",
        "title": page_title,
        "domain": parsed.netloc or raw,
        "category": f"External Target ({', '.join(tech_stack[:2])})",
        "tech_stack": tech_stack,
        "status_code": status_code,
        "latency_ms": latency_ms,
        "latency_profile": latency_profile,
        "security_headers": security_headers,
        "frame_blocked": frame_blocked,
        "proxy_mode": "zifi_header_stripping_proxy",
        "forms_detected": forms_count,
        "interactive_elements": buttons_count,
        "agents_detected": agents_detected,
        "tools_detected": tools_detected,
        "endpoints": tools_detected,
        "probe_waves": probe_waves,
        "probe_summary": {
            "probes_sent": probes_sent,
            "probes_succeeded": probes_succeeded,
            "probes_errors": probes_errors,
        },
        "robots_txt_disallow": locals().get("robots_disallow", False),
        "content_type": content_type,
        "error_note": error_note,
        "vulnerabilities_without_gateway": vulnerabilities,
    }
    ext_recon["evaluation_report"] = build_four_pillar_evaluation(ext_recon)
    return ext_recon


def build_network_interceptor_events(
    recon: dict[str, Any],
    run_result: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build Chrome-DevTools-style network interceptor rows for Zifi Browser."""
    if not recon.get("has_active_agents", True):
        return []

    endpoints = recon.get("endpoints", [])
    ep_read = endpoints[0]["path"] if len(endpoints) > 0 else "/api/read"
    ep_write = endpoints[1]["path"] if len(endpoints) > 1 else "/api/write"
    ep_trace = endpoints[2]["path"] if len(endpoints) > 2 else "/api/trace"
    ep_action = endpoints[3]["path"] if len(endpoints) > 3 else "/api/refund"
    ep_del = endpoints[4]["path"] if len(endpoints) > 4 else "/api/delete"

    d = run_result["direct"]
    g = run_result["gateway"]
    measured_p50 = (g.get("latency_ms") or {}).get("p50") if isinstance(g.get("latency_ms"), dict) else None

    rows = [
        {
            "seq": 1,
            "wave": 1,
            "agent": "orchestrator-00",
            "agent_id": "orchestrator-00",
            "method": "GET",
            "url": ep_read,
            "endpoint": ep_read,
            "unprotected_status": "200 OK",
            "exposed_status": "200 OK",
            "gateway_status": "200 OK (Root Trace d=0)",
            "gateway_action": "GOAL_CREATED + TRACE_ROOT",
            "latency_ms": measured_p50,
            "target_zone": "zone-read",
        },
        {
            "seq": 2,
            "wave": 2,
            "agent": "reader-00..35 (36x)",
            "agent_id": "reader-00..35 (36x)",
            "method": "GET",
            "url": f"{ep_read}?burst=36",
            "endpoint": f"{ep_read}?burst=36",
            "unprotected_status": f"429 Too Many Requests ({_fmt_num(d.get('upstream_errors'))} failed!)",
            "exposed_status": f"429 Too Many Requests ({_fmt_num(d.get('upstream_errors'))} failed!)",
            "gateway_status": f"200 OK (36/36 served · {_fmt_num(g.get('deduplicated'))} coalesced)",
            "gateway_action": "SINGLEFLIGHT_DEDUP + ADMISSION_QUEUE",
            "latency_ms": measured_p50,
            "target_zone": "zone-read",
        },
        {
            "seq": 3,
            "wave": 3,
            "agent": "writer-00..07 (8x)",
            "agent_id": "writer-00..07 (8x)",
            "method": "POST",
            "url": ep_write,
            "endpoint": ep_write,
            "unprotected_status": f"200 OK ({_fmt_num(d.get('lost_updates'))} LOST UPDATES — race condition!)",
            "exposed_status": f"200 OK ({_fmt_num(d.get('lost_updates'))} LOST UPDATES — race condition!)",
            "gateway_status": f"200 OK (8/8 serialized · CAS v{_fmt_num(g.get('cas_version'))} · 0 lost)",
            "gateway_action": "LEASE_FENCING_TOKEN + CAS_STATE",
            "latency_ms": measured_p50,
            "target_zone": "zone-write",
        },
        {
            "seq": 4,
            "wave": 4,
            "agent": "tracer-d1..d4 (Tree)",
            "agent_id": "tracer-d1..d4 (Tree)",
            "method": "GET",
            "url": f"{ep_trace}?depth=1..4",
            "endpoint": f"{ep_trace}?depth=1..4",
            "unprotected_status": f"200 OK (Unbounded recursion to depth {_fmt_num(d.get('depth_reached'))})",
            "exposed_status": f"200 OK (Unbounded recursion to depth {_fmt_num(d.get('depth_reached'))})",
            "gateway_status": f"429 budget_exceeded ({_fmt_num(g.get('depth_denied'))} halted at max_depth={_fmt_num(g.get('depth_limit'))})",
            "gateway_action": "DEPTH_BUDGET_ENFORCED",
            "latency_ms": measured_p50,
            "target_zone": "zone-trace",
        },
        {
            "seq": 5,
            "wave": 5,
            "agent": "reader-audit-01",
            "agent_id": "reader-audit-01",
            "method": "DELETE",
            "url": ep_del,
            "endpoint": ep_del,
            "unprotected_status": "200 OK (SECRET RECORD DELETED!)",
            "exposed_status": "200 OK (SECRET RECORD DELETED!)",
            "gateway_status": f"403 Forbidden ({g.get('deny_reason', 'read_only_agent')})",
            "gateway_action": "YAML_POLICY_DENIED",
            "latency_ms": measured_p50,
            "target_zone": "zone-delete",
        },
        {
            "seq": 6,
            "wave": 6,
            "agent": "support-lead-01",
            "agent_id": "support-lead-01",
            "method": "POST",
            "url": ep_action,
            "endpoint": ep_action,
            "unprotected_status": "200 OK (High-value $280+ executed without review!)",
            "exposed_status": "200 OK (High-value $280+ executed without review!)",
            "gateway_status": f"202 Pending Approval (id={str(g.get('approval_id', ''))[:8]})",
            "gateway_action": "HUMAN_APPROVAL_GATE_PAUSED",
            "latency_ms": measured_p50,
            "target_zone": "zone-approve",
        },
    ]
    return rows


def render_builtin_target_html(slug: str) -> str:
    """Render a zero-scrollbar Risograph Audit Print target web app inside Zifi Browser."""
    if slug == "sentinel-console":
        title = "SENTINEL OPS · US-EAST-1 CLUSTER"
        stamp_bg = "#00838A"
        stamp_fg = "#F1EADB"
        badge = "READY · 4 ENDPOINTS · 48 POLLERS + 12 WRITERS"
        zones = [
            {
                "id": "zone-read",
                "title": "01 / TELEMETRY API",
                "path": "GET /clusters/telemetry",
                "agents": "reader-00..47 (48× Telemetry Pollers)",
                "guardrail": "dedup.py + admission.py",
                "viz": '<span class="nd"></span>' * 12 + '<span class="viz-lbl">48x burst</span>',
                "idle_desc": "Raw endpoint: 48 concurrent pollers flooding telemetry backend without admission queue (Risk: 429 storm)",
                "before_id": "before-read",
                "before_default": "48 raw concurrent polls → 429 overload risk",
                "after_id": "state-read",
                "after_default": "Singleflight + 1s TTL cache + admission cap=3",
            },
            {
                "id": "zone-write",
                "title": "02 / REPLICA STATE",
                "path": "POST /runbooks/increment",
                "agents": "writer-00..11 (12× Failover Mutators)",
                "guardrail": "locks.py + state.py",
                "viz": '<span class="tk">T1</span><span class="tk">T2</span><span class="tk">T3</span><span class="tk">T4</span><span class="tk">..T12</span><span class="viz-lbl">fenced leases</span>',
                "idle_desc": "Raw mutator: 12 parallel writers mutating replica counter without CAS or leases (Risk: silent lost updates)",
                "before_id": "before-write",
                "before_default": "12 concurrent writes without locks → lost updates",
                "after_id": "state-write",
                "after_default": "Monotonic fencing_token + CAS If-Match v0→v12",
            },
            {
                "id": "zone-trace",
                "title": "03 / MESH TRACER",
                "path": "GET /mesh/dependency-trace",
                "agents": "tracer-d0..d4 (2^d Recursive Sub-Agents)",
                "guardrail": "budgets.py (max_depth=3)",
                "viz": '<span class="tk">d0</span>→<span class="tk">d1</span>→<span class="tk">d2</span>→<span class="tk">d3</span>✂<span class="tk cut">d4</span>',
                "idle_desc": "Unbounded mesh: Circular microservice call chains expanding without depth cap (Risk: cascading recursion loop)",
                "before_id": "before-trace",
                "before_default": "Unbounded binary fan-out expands to depth d=4",
                "after_id": "state-trace",
                "after_default": "Lineage tracker halts runaway tree at max_depth=3",
            },
            {
                "id": "zone-approve",
                "title": "04 / POLICY & SLA GATE",
                "path": "DELETE /vault + POST /credit ($320)",
                "agents": "reader-audit-01 + support-lead-01",
                "guardrail": "policy.py (YAML + Human Gate)",
                "viz": '<span class="tk cut">DEL:DENY</span><span class="tk ylw">$320:HOLD</span><span class="viz-lbl">RBAC + Gate</span>',
                "idle_desc": "Ungated policy: Read-only agent can delete production shard; $320 SLA credit executes without human sign-off",
                "before_id": "before-approve",
                "before_default": "Read-only agent deletes vault & $320 auto-runs",
                "after_id": "state-approve",
                "after_default": "read_only_agent denied · $320 paused for human",
            },
        ]
    elif slug == "quant-desk":
        title = "QUANTPULSE · NVDA ORDER BOOK & NAV"
        stamp_bg = "#FFE800"
        stamp_fg = "#1B1A17"
        badge = "READY · 4 ENDPOINTS · 64 POLLERS + 16 WRITERS"
        zones = [
            {
                "id": "zone-read",
                "title": "01 / ORDER BOOK FEED",
                "path": "GET /quotes/NVDA-book",
                "agents": "reader-00..63 (64× Quote Pollers)",
                "guardrail": "dedup.py + admission.py",
                "viz": '<span class="nd"></span>' * 12 + '<span class="viz-lbl">64x burst</span>',
                "idle_desc": "Raw market feed: 64 concurrent quote pollers hitting NVDA book directly (Risk: 429 rate-limit reject)",
                "before_id": "before-read",
                "before_default": "64 raw market-data reads → 429 feed rejection",
                "after_id": "state-read",
                "after_default": "Singleflight coalescing + admission queue cap=3",
            },
            {
                "id": "zone-write",
                "title": "02 / NAV LEDGER",
                "path": "POST /ledger/nav-adjust",
                "agents": "writer-00..15 (16× Margin Lot Writers)",
                "guardrail": "locks.py + state.py",
                "viz": '<span class="tk">T1</span><span class="tk">T2</span><span class="tk">T3</span><span class="tk">T4</span><span class="tk">..T16</span><span class="viz-lbl">fenced leases</span>',
                "idle_desc": "Raw ledger: 16 parallel margin adjusters colliding on lot counter (Risk: silent lost updates & ledger drift)",
                "before_id": "before-write",
                "before_default": "16 parallel NAV updates collide → lost lots",
                "after_id": "state-write",
                "after_default": "Serialized via fencing_token + CAS v0→v16",
            },
            {
                "id": "zone-trace",
                "title": "03 / EXPOSURE TREE",
                "path": "GET /exposure/chain",
                "agents": "tracer-d0..d4 (2^d Derivative Sub-Agents)",
                "guardrail": "budgets.py (max_depth=3)",
                "viz": '<span class="tk">d0</span>→<span class="tk">d1</span>→<span class="tk">d2</span>→<span class="tk">d3</span>✂<span class="tk cut">d4</span>',
                "idle_desc": "Unbounded tree: Multi-factor counterparty risk tree expanding without depth budget (Risk: factor recursion bomb)",
                "before_id": "before-trace",
                "before_default": "Recursive derivative chain runs unchecked to d=4",
                "after_id": "state-trace",
                "after_default": "Prunes sub-agent spawn at max_depth=3",
            },
            {
                "id": "zone-approve",
                "title": "04 / SETTLEMENT GATE",
                "path": "DELETE /blotter + POST /wire ($450)",
                "agents": "reader-audit-01 + support-lead-01",
                "guardrail": "policy.py (YAML + Human Gate)",
                "viz": '<span class="tk cut">DEL:DENY</span><span class="tk ylw">$450:HOLD</span><span class="viz-lbl">RBAC + Gate</span>',
                "idle_desc": "Ungated settlement: Read-only researcher can wipe blotter; $450 wire transfer executes without compliance approval",
                "before_id": "before-approve",
                "before_default": "Blotter deleted + $450 wire sent without review",
                "after_id": "state-approve",
                "after_default": "read_only_agent denied · $450 paused for human",
            },
        ]
    elif slug == "java-spring-jss":
        title = "JAVA SPRING AI · LANGCHAIN4J · JSS / JSP PORTAL"
        stamp_bg = "#00838A"
        stamp_fg = "#F1EADB"
        badge = "SPRING BOOT 3.4 · 42 POLLERS + 10 WRITERS"
        zones = [
            {
                "id": "zone-read",
                "title": "01 / SPRING AI CATALOG (.JSP)",
                "path": "GET /api/v3/orders/catalog.jsp",
                "agents": "lc4j-reader-00..41 (42× LangChain4j AiServices)",
                "guardrail": "dedup.py + admission.py",
                "viz": '<span class="nd"></span>' * 12 + '<span class="viz-lbl">42x burst</span>',
                "idle_desc": "Raw JSP catalog: 42 LangChain4j agents burst-polling /catalog.jsp concurrently (Risk: Tomcat 429 overload)",
                "before_id": "before-read",
                "before_default": "42× ChatClient / JSP reads → Tomcat 429 overload",
                "after_id": "state-read",
                "after_default": "Singleflight coalesced + admission queue cap=3",
            },
            {
                "id": "zone-write",
                "title": "02 / JPA / JSF STOCK (.DO)",
                "path": "POST /inventory/reserveStock.do",
                "agents": "jpa-writer-00..09 (10× JPA Mutators)",
                "guardrail": "locks.py + state.py",
                "viz": '<span class="tk">T1</span><span class="tk">T2</span><span class="tk">T3</span><span class="tk">T4</span><span class="tk">..T10</span><span class="viz-lbl">fenced leases</span>',
                "idle_desc": "Raw JPA state: 10 parallel Hibernate transactions mutating entity without CAS version (Risk: lost updates)",
                "before_id": "before-write",
                "before_default": "10 concurrent JPA/JSF ViewState writes → lost updates",
                "after_id": "state-write",
                "after_default": "Fenced lease tokens + CAS If-Match v0→v10",
            },
            {
                "id": "zone-trace",
                "title": "03 / SPRING MCP SSE TRACER",
                "path": "GET /mcp/message/trace-hop",
                "agents": "mcp-tracer-d0..d4 (2^d @McpTool Sub-Agents)",
                "guardrail": "budgets.py (max_depth=3)",
                "viz": '<span class="tk">d0</span>→<span class="tk">d1</span>→<span class="tk">d2</span>→<span class="tk">d3</span>✂<span class="tk cut">d4</span>',
                "idle_desc": "Unbounded MCP tree: Recursive Spring AI tool invocation hops expanding without max_depth (Risk: MCP tree loop)",
                "before_id": "before-trace",
                "before_default": "Recursive @McpTool tree spawns 31 calls to d=4",
                "after_id": "state-trace",
                "after_default": "Goal budget halts MCP recursion at max_depth=3",
            },
            {
                "id": "zone-approve",
                "title": "04 / ACTUATOR & ACTION GATE",
                "path": "DELETE /actuator/log + POST .action",
                "agents": "jsf-audit-reader-01 + treasury-approver-01",
                "guardrail": "policy.py (YAML + Human Gate)",
                "viz": '<span class="tk cut">DEL:DENY</span><span class="tk ylw">$280:HOLD</span><span class="viz-lbl">RBAC + Gate</span>',
                "idle_desc": "Ungated actuator: Read-only agent can delete /actuator/log; $280 refund auto-executes without @PreAuthorize gate",
                "before_id": "before-approve",
                "before_default": "Actuator audit purged + $280 .action auto-ran!",
                "after_id": "state-approve",
                "after_default": "DELETE denied (read_only) · $280 paused for human",
            },
        ]
    else:
        title = "AEGIS COMMERCE · FLASH SALE PORTAL"
        stamp_bg = "#FF48B0"
        stamp_fg = "#1B1A17"
        badge = "READY · 4 ENDPOINTS · 36 READERS + 8 WRITERS"
        zones = [
            {
                "id": "zone-read",
                "title": "01 / VIP ORDER CATALOG",
                "path": "GET /orders/order-hot-901",
                "agents": "reader-00..35 (36× Catalog Sub-Agents)",
                "guardrail": "dedup.py + admission.py",
                "viz": '<span class="nd"></span>' * 12 + '<span class="viz-lbl">36x burst</span>',
                "idle_desc": "Raw endpoint: 36 burst queries hitting catalog backend without singleflight or admission queue (Risk: 429 storm)",
                "before_id": "before-read",
                "before_default": "36 duplicate SKU reads → 429 overload storm",
                "after_id": "state-read",
                "after_default": "Singleflight coalesced + admission queue cap=3",
            },
            {
                "id": "zone-write",
                "title": "02 / STOCK LEDGER",
                "path": "POST /inventory/sku-77",
                "agents": "writer-00..07 (8× Inventory Writers)",
                "guardrail": "locks.py + state.py",
                "viz": '<span class="tk">T1</span><span class="tk">T2</span><span class="tk">T3</span><span class="tk">T4</span><span class="tk">..T8</span><span class="viz-lbl">fenced leases</span>',
                "idle_desc": "Raw mutator: 8 parallel writers mutating SKU stock concurrently without CAS or leases (Risk: silent lost updates)",
                "before_id": "before-write",
                "before_default": "8 concurrent SKU decrements → silent lost writes",
                "after_id": "state-write",
                "after_default": "Fenced lease tokens + CAS version check v0→v8",
            },
            {
                "id": "zone-trace",
                "title": "03 / SHIPMENT TRACER",
                "path": "GET /shipments/trace-hop",
                "agents": "tracer-d0..d4 (2^d Carrier Sub-Agents)",
                "guardrail": "budgets.py (max_depth=3)",
                "viz": '<span class="tk">d0</span>→<span class="tk">d1</span>→<span class="tk">d2</span>→<span class="tk">d3</span>✂<span class="tk cut">d4</span>',
                "idle_desc": "Unbounded tree: Recursive carrier hop tracers expanding without max_depth budget (Risk: exponential fan-out)",
                "before_id": "before-trace",
                "before_default": "Runaway carrier tree spawns 31 calls to depth d=4",
                "after_id": "state-trace",
                "after_default": "Goal budget halts recursion cleanly at max_depth=3",
            },
            {
                "id": "zone-approve",
                "title": "04 / REFUND & AUDIT GATE",
                "path": "DELETE /log + POST /refund ($280)",
                "agents": "reader-audit-01 + support-lead-01",
                "guardrail": "policy.py (YAML + Human Gate)",
                "viz": '<span class="tk cut">DEL:DENY</span><span class="tk ylw">$280:HOLD</span><span class="viz-lbl">RBAC + Gate</span>',
                "idle_desc": "Ungated actions: Read-only agent can delete audit log; $280 VIP refund auto-executes without human sign-off",
                "before_id": "before-approve",
                "before_default": "Audit log deleted + $280 refund auto-executed!",
                "after_id": "state-approve",
                "after_default": "DELETE denied (read_only) · $280 paused for human",
            },
        ]

    cards_html = ""
    for z in zones:
        cards_html += f"""
    <div class="zone-card" id="{z['id']}">
      <div class="zone-head">
        <span class="zone-title">{html.escape(z['title'])}</span>
        <span class="zone-path">{html.escape(z['path'])}</span>
      </div>

      <div class="agent-strip">
        <span class="agent-who">SWARM: {html.escape(z['agents'])}</span>
        <span class="agent-viz">{z['viz']}</span>
      </div>

      <!-- Initial idle state: visible before RUN AUDIT -->
      <div class="idle-status-box" id="{z['id']}-idle">
        <div class="idle-status-tag">RAW ENDPOINT · STANDBY</div>
        <div class="idle-status-text">{html.escape(z.get('idle_desc', 'Raw unmitigated endpoint'))}</div>
      </div>

      <!-- Before vs After comparison: revealed during and after RUN AUDIT -->
      <div class="ba-box" id="{z['id']}-ba" style="display: none;">
        <div class="ba-row ba-before">
          <span class="ba-tag pink">BEFORE</span>
          <span class="ba-text" id="{z['before_id']}">{html.escape(z['before_default'])}</span>
        </div>
        <div class="ba-row ba-after">
          <span class="ba-tag teal">AFTER</span>
          <span class="ba-text" id="{z['after_id']}">{html.escape(z['after_default'])}</span>
        </div>
      </div>

      <div class="zone-foot">
        <span class="guardrail-tag">MODULE: {html.escape(z['guardrail'])}</span>
        <span class="mini-stamp" data-card-stamp>STANDBY</span>
      </div>
    </div>"""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html.escape(title)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@500;600&display=swap" rel="stylesheet">
  <style>
    * {{ box-sizing: border-box; }}
    html, body {{
      margin: 0;
      padding: 0;
      height: 100%;
      overflow: hidden;
      font-family: 'IBM Plex Sans', -apple-system, sans-serif;
      background: #F1EADB;
      color: #1B1A17;
    }}
    .wrap {{
      padding: 10px 12px;
      height: 100%;
      display: flex;
      flex-direction: column;
      gap: 8px;
      background-image: radial-gradient(#C8BEA9 1px, transparent 1px);
      background-size: 12px 12px;
    }}
    .top-bar {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      border: 1.5px solid #1B1A17;
      background: #E4DAC4;
      flex-shrink: 0;
    }}
    .top-title {{
      padding: 5px 10px;
      font-weight: 600;
      font-size: 11.5px;
      letter-spacing: 0.04em;
      display: flex;
      align-items: center;
      gap: 8px;
      color: #1B1A17;
    }}
    .sq {{
      width: 9px;
      height: 9px;
      background: {stamp_bg};
      border: 1.5px solid #1B1A17;
    }}
    .top-status {{
      padding: 5px 10px;
      background: {stamp_bg};
      color: {stamp_fg};
      border-left: 1.5px solid #1B1A17;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 10.5px;
      font-weight: 600;
    }}
    .grid {{
      flex: 1;
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      grid-template-rows: minmax(0, 1fr) minmax(0, 1fr);
      gap: 8px;
      min-height: 0;
      min-width: 0;
      width: 100%;
    }}
    .zone-card {{
      border: 1.5px solid #1B1A17;
      background: #F1EADB;
      padding: 8px 10px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      box-shadow: 3px 3px 0 #E4DAC4;
      position: relative;
      transition: background-color 160ms ease-out, box-shadow 160ms ease-out, border-color 160ms ease-out;
      min-height: 0;
      min-width: 0;
      overflow: hidden;
    }}
    .zone-card.mode-exposed {{
      background: #F9DFEC;
      border-color: #1B1A17;
      box-shadow: 3px 3px 0 #FF48B0;
    }}
    .zone-card.mode-protected {{
      background: #E6F2F2;
      border-color: #1B1A17;
      box-shadow: 3px 3px 0 #00838A;
    }}
    .zone-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 4px;
      border-bottom: 1px solid #1B1A17;
      padding-bottom: 4px;
      min-width: 0;
    }}
    .zone-title {{
      font-weight: 600;
      font-size: 11px;
      letter-spacing: 0.02em;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .zone-path {{
      font-family: 'IBM Plex Mono', monospace;
      font-size: 9px;
      font-weight: 600;
      padding: 1px 5px;
      border: 1px solid #1B1A17;
      background: #E4DAC4;
      color: #1B1A17;
      white-space: nowrap;
      flex-shrink: 0;
    }}
    /* Agent Swarm Activity Strip */
    .agent-strip {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 4px;
      background: #E4DAC4;
      border: 1px solid #1B1A17;
      padding: 3px 6px;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 9.5px;
      min-width: 0;
      overflow: hidden;
    }}
    .agent-who {{
      font-weight: 600;
      color: #1B1A17;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      min-width: 0;
    }}
    .agent-viz {{
      display: inline-flex;
      align-items: center;
      gap: 2px;
      flex-shrink: 0;
      font-size: 9px;
      font-weight: 600;
    }}
    .nd {{
      width: 5px;
      height: 7px;
      background: #00838A;
      border: 1px solid #1B1A17;
      display: inline-block;
    }}
    .zone-card.mode-exposed .nd {{
      background: #FF48B0;
    }}
    .tk {{
      padding: 0 3px;
      border: 1px solid #1B1A17;
      background: #F1EADB;
      font-size: 8.5px;
    }}
    .tk.cut {{
      background: #FF48B0;
      color: #1B1A17;
      text-decoration: line-through;
    }}
    .tk.ylw {{
      background: #FFE800;
      color: #1B1A17;
    }}
    .viz-lbl {{
      margin-left: 2px;
      color: #6B6559;
      font-size: 8.5px;
    }}
    /* Before vs After comparison rows inside each card */
    .idle-status-box {{
      display: flex;
      flex-direction: column;
      gap: 3px;
      padding: 5px 7px;
      border: 1px dashed #6B6559;
      background: rgba(241, 234, 219, 0.95);
      font-family: 'IBM Plex Mono', monospace;
      font-size: 9.5px;
      line-height: 1.3;
      min-width: 0;
    }}
    .idle-status-tag {{
      font-size: 8.5px;
      font-weight: 600;
      letter-spacing: 0.05em;
      color: #b33900;
      text-transform: uppercase;
    }}
    .idle-status-text {{
      color: #1B1A17;
      font-weight: 500;
      overflow: hidden;
      text-overflow: ellipsis;
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
    }}
    .mode-exposed .idle-status-box,
    .mode-protected .idle-status-box {{
      display: none !important;
    }}
    .mode-exposed .ba-box,
    .mode-protected .ba-box {{
      display: flex !important;
    }}
    .mode-exposed .ba-row.ba-after {{
      opacity: 0.35;
      filter: grayscale(0.9);
    }}
    .mode-protected .ba-row.ba-after {{
      opacity: 1;
      filter: none;
    }}
    .ba-box {{
      display: flex;
      flex-direction: column;
      gap: 4px;
      min-width: 0;
    }}
    .ba-row {{
      display: grid;
      grid-template-columns: 48px minmax(0, 1fr);
      align-items: center;
      gap: 5px;
      padding: 3px 5px;
      border: 1px dashed #6B6559;
      background: rgba(241, 234, 219, 0.85);
      font-family: 'IBM Plex Mono', monospace;
      font-size: 9.5px;
      line-height: 1.25;
      min-width: 0;
    }}
    .ba-row.ba-before {{
      border-left: 3px solid #FF48B0;
    }}
    .ba-row.ba-after {{
      border-left: 3px solid #00838A;
    }}
    .ba-tag {{
      font-size: 9px;
      font-weight: 600;
      text-align: center;
      padding: 1px 3px;
      border: 1px solid #1B1A17;
      letter-spacing: 0.04em;
    }}
    .ba-tag.pink {{
      background: #FF48B0;
      color: #1B1A17;
    }}
    .ba-tag.teal {{
      background: #00838A;
      color: #F1EADB;
    }}
    .ba-text {{
      color: #1B1A17;
      font-weight: 600;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    /* Card Footer + Mini Stamp */
    .zone-foot {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-top: 2px;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 9.5px;
      color: #6B6559;
    }}
    .guardrail-tag {{
      font-weight: 600;
    }}
    .mini-stamp {{
      padding: 1px 6px;
      border: 1.5px solid #1B1A17;
      background: #E4DAC4;
      color: #1B1A17;
      font-weight: 600;
      font-size: 9px;
      letter-spacing: 0.06em;
      transform: rotate(-2deg);
    }}
    .mini-stamp.stamped-exposed {{
      background: #FF48B0;
      color: #1B1A17;
      animation: miniSlam 320ms cubic-bezier(0.22, 1, 0.36, 1) forwards;
    }}
    .mini-stamp.stamped-protected {{
      background: #00838A;
      color: #F1EADB;
      border-style: double;
      border-width: 2.5px;
      animation: miniSlam 380ms cubic-bezier(0.22, 1, 0.36, 1) forwards;
    }}
    @keyframes miniSlam {{
      0%   {{ transform: scale(2.4) rotate(-14deg); opacity: 0; }}
      65%  {{ transform: scale(0.92) rotate(-2deg); opacity: 1; }}
      100% {{ transform: scale(1) rotate(-2.5deg); opacity: 1; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top-bar">
      <div class="top-title"><span class="sq"></span><span>{html.escape(title)}</span></div>
      <div class="top-status" id="app-mode-pill">{html.escape(badge)}</div>
    </div>
    <div class="grid">{cards_html}
    </div>
  </div>
  <script>
    window.addEventListener("message", (event) => {{
      const msg = event.data || {{}};
      if (msg.type === "ZIFI_WAVE") {{
        const isProtected = Boolean(msg.protected);
        document.querySelectorAll(".zone-card").forEach(el => {{
          el.classList.remove("mode-exposed", "mode-protected");
          el.classList.add(isProtected ? "mode-protected" : "mode-exposed");
        }});
        document.querySelectorAll(".idle-status-box").forEach(b => b.style.display = "none");
        document.querySelectorAll(".ba-box").forEach(b => b.style.display = "flex");
        document.querySelectorAll("[data-card-stamp]").forEach(st => {{
          st.classList.remove("stamped-exposed", "stamped-protected");
          void st.offsetWidth;
          if (isProtected) {{
            st.textContent = "⊕ PROTECTED";
            st.classList.add("stamped-protected");
          }} else {{
            st.textContent = "⊗ EXPOSED";
            st.classList.add("stamped-exposed");
          }}
        }});
        if (msg.beforeRead) document.getElementById("before-read").textContent = msg.beforeRead;
        if (msg.beforeWrite) document.getElementById("before-write").textContent = msg.beforeWrite;
        if (msg.beforeTrace) document.getElementById("before-trace").textContent = msg.beforeTrace;
        if (msg.beforeApprove) document.getElementById("before-approve").textContent = msg.beforeApprove;

        if (msg.readText) document.getElementById("state-read").textContent = msg.readText;
        if (msg.writeText) document.getElementById("state-write").textContent = msg.writeText;
        if (msg.traceText) document.getElementById("state-trace").textContent = msg.traceText;
        if (msg.approveText) document.getElementById("state-approve").textContent = msg.approveText;
        if (msg.pillText) document.getElementById("app-mode-pill").textContent = msg.pillText;
      }}
      if (msg.type === "ZIFI_RESET") {{
        document.querySelectorAll(".zone-card").forEach(el => {{
          el.classList.remove("mode-exposed", "mode-protected");
        }});
        document.querySelectorAll(".idle-status-box").forEach(b => b.style.display = "flex");
        document.querySelectorAll(".ba-box").forEach(b => b.style.display = "none");
        document.querySelectorAll("[data-card-stamp]").forEach(st => {{
          st.textContent = "STANDBY";
          st.className = "mini-stamp";
        }});
        document.getElementById("app-mode-pill").textContent = "{html.escape(badge)}";
      }}
    }});
  </script>
</body>
</html>"""

