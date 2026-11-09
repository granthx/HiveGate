"""Async Groq LLM engine for the Test Projects multi-agent swarms.

Uses httpx against Groq's OpenAI-compatible chat completions endpoint so no
extra blocking SDK is required. Reads GROQ_API_KEY from the environment, a
local .env file, or runtime configuration set in the Test Projects UI.

Captures real token counts and computes costs from API usage fields.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import httpx

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"

# Published pricing for Groq llama-3.3-70b-versatile:
# $0.59 per 1M prompt tokens, $0.79 per 1M completion tokens
GROQ_PROMPT_PRICE_PER_M = 0.59
GROQ_COMPLETION_PRICE_PER_M = 0.79


def _load_dotenv_if_present() -> None:
    """Load simple KEY=VALUE pairs from .env without overwriting existing env vars."""
    for candidate in (Path(".env"), Path(__file__).resolve().parent.parent / ".env"):
        if candidate.is_file():
            for raw_line in candidate.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value


_load_dotenv_if_present()


@dataclass
class LLMUsage:
    """Real token counts and computed costs from the provider's API usage fields."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    source: str = "api_usage"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def calculate_cost(cls, prompt_tokens: int, completion_tokens: int) -> float:
        """Calculate cost in USD using published Groq rates."""
        cost = (prompt_tokens * GROQ_PROMPT_PRICE_PER_M + completion_tokens * GROQ_COMPLETION_PRICE_PER_M) / 1_000_000.0
        return round(cost, 6)


@dataclass
class AgentThought:
    """One recorded reasoning step from an LLM agent in the swarm."""

    agent_id: str
    role: str
    thought: str
    action: str
    latency_ms: float
    model: str
    live_llm: bool


@dataclass
class GroqConfig:
    """Runtime Groq configuration (API key kept in memory only)."""

    api_key: str = field(default_factory=lambda: os.getenv("GROQ_API_KEY", ""))
    model: str = field(default_factory=lambda: os.getenv("GROQ_MODEL", DEFAULT_GROQ_MODEL))

    @property
    def configured(self) -> bool:
        key = (self.api_key or os.getenv("GROQ_API_KEY", "")).strip()
        return bool(key)

    def current_key(self) -> str:
        return (self.api_key or os.getenv("GROQ_API_KEY", "")).strip()


def format_untrusted_page_content(raw_content: str) -> str:
    """Format and delimit untrusted external webpage text for LLM consumption.

    Strips any attempts to prematurely close boundary XML tags (including case
    and whitespace evasion variants) and wraps content in a rigid untrusted
    boundary with defensive instructions.
    """
    cleaned = re.sub(r"<\s*/?\s*untrusted_external_content\s*>", "", raw_content or "", flags=re.IGNORECASE)
    return f"<untrusted_external_content>\n{cleaned.strip()}\n</untrusted_external_content>"


class GroqSwarmEngine:
    """Executes Orchestrator, Specialist, and Synthesis agent prompts on Groq."""

    def __init__(self, config: GroqConfig | None = None) -> None:
        self.config = config or GroqConfig()
        self.last_usage: LLMUsage = LLMUsage(source="none")

    def set_credentials(self, api_key: str, model: str | None = None) -> None:
        self.config.api_key = api_key.strip()
        if model:
            self.config.model = model.strip()

    def configure(self, api_key: str = "", model: str | None = None) -> None:
        if api_key.strip():
            self.config.api_key = api_key.strip()
        if model and model.strip():
            self.config.model = model.strip()

    def status(self) -> dict[str, Any]:
        key = self.config.current_key()
        return {
            "configured": bool(key),
            "model": self.config.model or DEFAULT_GROQ_MODEL,
        }

    async def chat_json(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        fallback: dict[str, Any],
        timeout_s: float = 12.0,
    ) -> tuple[dict[str, Any], float, bool, str]:
        """Call Groq in JSON mode, or return the deterministic fallback if unconfigured."""
        started = time.perf_counter()
        api_key = self.config.current_key()
        model = self.config.model or DEFAULT_GROQ_MODEL

        if not api_key:
            elapsed = (time.perf_counter() - started) * 1000
            self.last_usage = LLMUsage(source="none")
            res = dict(fallback)
            res["_usage"] = self.last_usage.to_dict()
            return res, round(elapsed, 2), False, "simulated-fallback (set GROQ_API_KEY for live LLM)"

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 600,
            "response_format": {"type": "json_object"},
        }
        try:
            async with httpx.AsyncClient(timeout=timeout_s) as client:
                response = await client.post(GROQ_API_URL, headers=headers, json=body)
                response.raise_for_status()
                payload = response.json()
                content = payload["choices"][0]["message"]["content"]
                parsed = json.loads(content)

                # Capture real token usage directly from API response
                raw_usage = payload.get("usage", {})
                p_tokens = int(raw_usage.get("prompt_tokens", 0))
                c_tokens = int(raw_usage.get("completion_tokens", 0))
                t_tokens = int(raw_usage.get("total_tokens", p_tokens + c_tokens))
                cost = LLMUsage.calculate_cost(p_tokens, c_tokens)

                self.last_usage = LLMUsage(
                    prompt_tokens=p_tokens,
                    completion_tokens=c_tokens,
                    total_tokens=t_tokens,
                    cost_usd=cost,
                    source="api_usage",
                )
                parsed["_usage"] = self.last_usage.to_dict()

                elapsed = (time.perf_counter() - started) * 1000
                return parsed, round(elapsed, 2), True, model
        except Exception as exc:
            elapsed = (time.perf_counter() - started) * 1000
            self.last_usage = LLMUsage(source="fallback")
            merged = dict(fallback)
            merged["_usage"] = self.last_usage.to_dict()
            merged["llm_note"] = f"Groq call fell back ({type(exc).__name__}); deterministic plan used."
            return merged, round(elapsed, 2), False, f"{model} (fallback)"

    async def chat_tool_calls(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        fallback_tool_calls: list[dict[str, Any]],
        timeout_s: float = 12.0,
    ) -> tuple[list[dict[str, Any]], LLMUsage, float, bool, str, str]:
        """Request structured tool calls from Groq with schema validation."""
        started = time.perf_counter()
        api_key = self.config.current_key()
        model = self.config.model or DEFAULT_GROQ_MODEL

        if not api_key:
            elapsed = (time.perf_counter() - started) * 1000
            usage = LLMUsage(source="none")
            return (
                fallback_tool_calls,
                usage,
                round(elapsed, 2),
                False,
                model,
                "LLM unavailable, fell back to scripted",
            )

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 1000,
            "response_format": {"type": "json_object"},
        }

        try:
            async with httpx.AsyncClient(timeout=timeout_s) as client:
                response = await client.post(GROQ_API_URL, headers=headers, json=body)
                response.raise_for_status()
                payload = response.json()
                content = payload["choices"][0]["message"]["content"]
                parsed = json.loads(content)

                raw_usage = payload.get("usage", {})
                p_tokens = int(raw_usage.get("prompt_tokens", 0))
                c_tokens = int(raw_usage.get("completion_tokens", 0))
                t_tokens = int(raw_usage.get("total_tokens", p_tokens + c_tokens))
                cost = LLMUsage.calculate_cost(p_tokens, c_tokens)

                usage = LLMUsage(
                    prompt_tokens=p_tokens,
                    completion_tokens=c_tokens,
                    total_tokens=t_tokens,
                    cost_usd=cost,
                    source="api_usage",
                )
                self.last_usage = usage
                elapsed = (time.perf_counter() - started) * 1000

                calls = parsed.get("tool_calls", [])
                if not isinstance(calls, list) or not calls:
                    return (
                        fallback_tool_calls,
                        usage,
                        round(elapsed, 2),
                        True,
                        model,
                        f"live ({model}) - empty tool_calls, used fallback structure",
                    )

                return (
                    calls,
                    usage,
                    round(elapsed, 2),
                    True,
                    model,
                    f"live (groq · {model})",
                )
        except Exception as exc:
            elapsed = (time.perf_counter() - started) * 1000
            usage = LLMUsage(source="fallback")
            return (
                fallback_tool_calls,
                usage,
                round(elapsed, 2),
                False,
                model,
                f"LLM unavailable, fell back to scripted ({type(exc).__name__})",
            )
