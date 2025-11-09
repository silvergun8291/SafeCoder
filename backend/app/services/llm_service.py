import os
from typing import Optional

from app.core.config import get_settings

# LangChain Upstage LLM
from langchain_upstage import ChatUpstage
from langchain_core.messages import SystemMessage, HumanMessage


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

    def ask(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
        ]
        try:
            response = self.llm.invoke(messages)
            return response.content
        except Exception as e:
            # In production, use structured logging
            print(f"LLM invocation failed: {e}")
            return None

