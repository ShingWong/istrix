"""Multi-provider LLM client for iStrix AI operations."""

import os
from pathlib import Path
from typing import Any

import yaml


class AIProvider:
    """Unified AI provider configuration and client.

    Supports: openai, anthropic, openrouter, ollama, lmstudio
    Configured via:
    1. config/ai.defaults.yaml (lowest priority)
    2. Environment variables: STRIX_AI_* (medium priority)
    3. Direct keyword arguments (highest priority)
    """

    def __init__(
        self,
        provider: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        api_base: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ):
        config = self._load_config()

        self.provider = provider or os.getenv("STRIX_AI_PROVIDER") or config.get("provider", "openai")
        self.model = model or os.getenv("STRIX_AI_MODEL") or config.get("model", "gpt-4o")
        self.api_key = api_key or os.getenv("STRIX_AI_API_KEY") or config.get("api_key")
        self.api_base = api_base or os.getenv("STRIX_AI_API_BASE") or config.get("api_base")
        self.temperature = temperature if temperature is not None else config.get("temperature", 0.7)
        self.max_tokens = max_tokens if max_tokens is not None else config.get("max_tokens", 4096)

        if self.provider == "openrouter" and self.api_base is None:
            self.api_base = "https://openrouter.ai/api/v1"

    DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent.parent / "config" / "ai.defaults.yaml"

    def _load_config(self) -> dict[str, Any]:
        try:
            with open(self.DEFAULT_CONFIG_PATH) as f:
                data = yaml.safe_load(f)
                return data.get("ai", {}) if data else {}
        except (FileNotFoundError, yaml.YAMLError):
            return {}

    def is_configured(self) -> bool:
        """Check if enough configuration is present to make API calls."""
        if self.provider in ("ollama", "lmstudio", "openrouter"):
            return self.api_base is not None and self.model is not None
        return self.api_key is not None

    def chat(self, messages: list[dict[str, str]]) -> str:
        """Send a chat completion request to the configured provider.

        Args:
            messages: List of messages with 'role' and 'content' keys.

        Returns:
            The assistant's response text.

        Raises:
            RuntimeError: If the provider is not configured or the call fails.
        """
        if not self.is_configured():
            raise RuntimeError(
                "AI provider not configured. Set STRIX_AI_API_KEY or run: istrix config init"
            )

        if self.provider == "openai":
            return self._chat_openai(messages)
        elif self.provider == "anthropic":
            return self._chat_anthropic(messages)
        elif self.provider == "openrouter":
            return self._chat_openai_compat(messages)
        elif self.provider in ("ollama", "lmstudio"):
            return self._chat_openai_compat(messages)
        else:
            raise RuntimeError(f"Unknown AI provider: {self.provider}")

    def _chat_openai(self, messages: list[dict[str, str]]) -> str:
        try:
            from langchain_openai import ChatOpenAI
        except ImportError:
            raise ImportError(
                "langchain-openai not installed. Run: pip install istrix[ai]"
            )

        llm = ChatOpenAI(
            model=self.model,
            api_key=self.api_key,
            base_url=self.api_base,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        response = llm.invoke(messages)
        return str(response.content)

    def _chat_anthropic(self, messages: list[dict[str, str]]) -> str:
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError:
            raise ImportError(
                "langchain-anthropic not installed. Run: pip install istrix[ai]"
            )

        llm = ChatAnthropic(
            model=self.model,
            api_key=self.api_key,
            base_url=self.api_base,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        response = llm.invoke(messages)
        return str(response.content)

    def _chat_openai_compat(self, messages: list[dict[str, str]]) -> str:
        try:
            from langchain_openai import ChatOpenAI
        except ImportError:
            raise ImportError(
                "langchain-openai not installed. Run: pip install istrix[ai]"
            )

        llm = ChatOpenAI(
            model=self.model,
            api_key=self.api_key or "not-needed",
            base_url=self.api_base,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        response = llm.invoke(messages)
        return str(response.content)


def get_llm(
    provider: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    api_base: str | None = None,
) -> AIProvider:
    """Create an AIProvider instance from configuration.

    Uses layered configuration: defaults < env vars < kwargs.

    Args:
        provider: AI provider name (openai, anthropic, ollama, lmstudio).
        model: Model name.
        api_key: API key for the provider.
        api_base: Base URL for the API (needed for Ollama/LM Studio).

    Returns:
        Configured AIProvider instance.
    """
    return AIProvider(
        provider=provider,
        model=model,
        api_key=api_key,
        api_base=api_base,
    )
