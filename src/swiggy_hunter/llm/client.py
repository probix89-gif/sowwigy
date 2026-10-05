"""
LLMClient — the single choke-point for every LLM call.

Responsibilities:
  - OpenAI-compatible POST to {base_url}/chat/completions
  - sliding-window rate limit + concurrency cap
  - token usage recording + budget gate
  - thinking window enforcement (via ThinkingController)
  - retries on 429 / 5xx / network
  - supports streaming=false; returns the raw assistant message
  - auto-detects reasoning_content blocks (GLM/GPT style)

Only this file talks to top-tools-ai.com. Everything else goes through
LLMClient.chat.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import aiohttp
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ..config import AppConfig
from ..logging_setup import get_logger
from .rate_limiter import SlidingWindowRateLimiter
from .thinking import ThinkingController
from .token_budget import AgentTokenBudget
from .usage import UsageTracker

log = get_logger(__name__)


class BudgetExceeded(Exception):
    """Raised when daily token budget is exhausted."""


class LLMError(Exception):
    """Non-retryable LLM error (4xx other than 429)."""


class _RetryableError(Exception):
    """Internal — flags a transient failure to tenacity."""


class LLMClient:
    def __init__(
        self,
        cfg: AppConfig,
        usage: UsageTracker,
        budget: AgentTokenBudget,
    ):
        self.cfg = cfg
        self.usage = usage
        self.budget = budget
        self.limiter = SlidingWindowRateLimiter(
            limit_per_minute=cfg.rate_limit.requests_per_minute,
            safety_margin=cfg.rate_limit.safety_margin,
            max_concurrent=cfg.rate_limit.max_concurrent,
        )
        self.thinking = ThinkingController(
            enabled=cfg.model.thinking_window.enabled,
            min_seconds=cfg.model.thinking_window.min_seconds,
            max_seconds=cfg.model.thinking_window.max_seconds,
            agents=cfg.model.thinking_window.agents,
        )
        self._session: aiohttp.ClientSession | None = None

    # ------------------------------------------------------------------
    # session
    # ------------------------------------------------------------------

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.cfg.model.thinking_window.max_seconds + 90),
                headers={"Content-Type": "application/json"},
            )
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    # ------------------------------------------------------------------
    # the actual HTTP call
    # ------------------------------------------------------------------

    def _endpoint(self) -> str:
        base = (self.cfg.model.base_url or "").rstrip("/")
        return f"{base}/chat/completions"

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=2, max=40),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError, _RetryableError)),
        reraise=True,
    )
    async def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        session = await self._ensure_session()
        url = self._endpoint()
        api_key = self.cfg.secrets.glm_api_key if self.cfg.secrets else ""
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        async with self.limiter():
            async with session.post(url, json=payload, headers=headers) as resp:
                body = await resp.text()
                status = resp.status

                if status == 429:
                    log.warning("llm.429", retry_after=resp.headers.get("retry-after"))
                    raise _RetryableError("upstream 429")
                if status >= 500:
                    log.warning("llm.5xx", status=status)
                    raise _RetryableError(f"server {status}")
                if status >= 400:
                    raise LLMError(f"LLM {status}: {body[:500]}")

                try:
                    return json.loads(body)
                except json.JSONDecodeError as e:
                    raise LLMError(f"bad json from gateway: {e}: {body[:300]}")

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    async def chat(
        self,
        agent: str,
        messages: list[dict[str, Any]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Send a chat request. Returns the raw assistant message dict:
            {"role": "assistant", "content": "...", "tool_calls": [...]?,
             "reasoning_content": "..."?}
        """
        if not await self.usage.can_spend(estimated=1000):
            raise BudgetExceeded("daily token budget exhausted")
        if not await self.budget.can_spend(agent, estimated=1000):
            raise BudgetExceeded(f"agent {agent} per-day budget exhausted")

        payload: dict[str, Any] = {
            "model": self.cfg.model.name,
            "messages": messages,
            "temperature": (
                temperature if temperature is not None
                else self.cfg.model.default_temperature
            ),
            "max_tokens": max_tokens or self.cfg.model.max_output_tokens,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice or "auto"
        if extra:
            payload.update(extra)

        # wrap in thinking controller if this agent opts in
        async def _do_call() -> dict[str, Any]:
            return await self._post(payload)

        data, timing = await self.thinking.wrap(agent, _do_call)

        usage = data.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens", 0))
        completion_tokens = int(usage.get("completion_tokens", 0))
        thinking_tokens = int(usage.get("completion_tokens_details", {}).get("reasoning_tokens", 0)) \
            if isinstance(usage.get("completion_tokens_details"), dict) else 0

        await self.usage.record(
            agent=agent,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            thinking_tokens=thinking_tokens,
        )
        await self.budget.record(agent, prompt_tokens + completion_tokens + thinking_tokens)

        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        # attach timing so agents can log it
        message.setdefault("_meta", {})["thinking"] = {
            "elapsed_s": timing.elapsed_s,
            "padded": timing.padded,
            "over_max": timing.over_max,
        }
        message.setdefault("_meta", {})["usage"] = {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "thinking_tokens": thinking_tokens,
        }
        return message

    # ------------------------------------------------------------------
    # convenience
    # ------------------------------------------------------------------

    async def raw_completion(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        msgs: list[dict[str, Any]] = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        msg = await self.chat("raw", msgs, temperature=temperature, max_tokens=max_tokens)
        return msg.get("content") or ""

    def stats(self) -> dict[str, Any]:
        return {
            "endpoint": self._endpoint(),
            "model": self.cfg.model.name,
            "rate": self.limiter.stats(),
            "thinking": self.thinking.describe(),
        }
