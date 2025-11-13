import asyncio
import hashlib
import os
import time
from typing import Optional, Dict, Any

from langchain_core.messages import SystemMessage, HumanMessage
# LangChain Upstage LLM
from langchain_upstage import ChatUpstage

from app.core.config import get_settings


class LLMService:
    """Minimal LLM wrapper to send system/user prompts and get a response."""

    def __init__(self, model: str = "solar-pro2", temperature: float = 0.0, top_p: float = 0.01, seed: int = 42):
        settings = get_settings()
        # Ensure API key is available to the SDK
        os.environ["UPSTAGE_API_KEY"] = settings.UPSTAGE_API_KEY

        self.llm = ChatUpstage(
            model=model,
            temperature=temperature,
            top_p=top_p,
            seed=seed,
            max_tokens=4096,
        )
        # Simple in-memory cache with optional TTL
        # _cache: {key: {"value": str, "ts": float}}
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_max = int(getattr(settings, "LLM_CACHE_MAX", 128) or 128)
        self._cache_ttl = int(getattr(settings, "LLM_CACHE_TTL_SECONDS", 0) or 0)

    def ask(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
        ]
        try:
            # cache lookup
            key = self._cache_key(system_prompt, user_prompt)
            cached = self._cache_get(key)
            if cached is not None:
                return cached
            response = self.llm.invoke(messages)
            content = getattr(response, "content", None)
            if content and isinstance(content, str):
                self._cache_store(key, content)
            return content
        except Exception as e:
            # In production, use structured logging
            print(f"LLM invocation failed: {e}")
            return None

    async def ask_async(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
        ]
        try:
            key = self._cache_key(system_prompt, user_prompt)
            cached = self._cache_get(key)
            if cached is not None:
                return cached
            # Offload blocking invoke to thread
            response = await asyncio.to_thread(self.llm.invoke, messages)
            content = getattr(response, "content", None)
            if content and isinstance(content, str):
                self._cache_store(key, content)
            return content
        except Exception as e:
            print(f"LLM async invocation failed: {e}")
            return None

    def _cache_key(self, system_prompt: str, user_prompt: str) -> str:
        h = hashlib.sha256()
        h.update(system_prompt.encode("utf-8", errors="ignore"))
        h.update(b"\x00")
        h.update(user_prompt.encode("utf-8", errors="ignore"))
        return h.hexdigest()

    def _cache_get(self, key: str) -> Optional[str]:
        try:
            item = self._cache.get(key)
            if not item:
                return None
            if self._cache_ttl > 0:
                if (time.time() - float(item.get("ts", 0))) > self._cache_ttl:
                    # expired
                    self._cache.pop(key, None)
                    return None
            return item.get("value")
        except Exception:
            return None

    def _cache_store(self, key: str, value: str) -> None:
        try:
            # simple FIFO-style eviction using insertion-ordered dict
            if len(self._cache) >= self._cache_max > 0:
                # remove first inserted key
                try:
                    self._cache.pop(next(iter(self._cache)))
                except StopIteration:
                    self._cache.clear()
            self._cache[key] = {"value": value, "ts": time.time()}
        except Exception:
            pass

