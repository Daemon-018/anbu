"""Minimal OpenAI-compatible chat client using only the standard library.

The project already depends on androguard; a second HTTP stack buys nothing.
Configure it with:

    ANBU_LLM_BASE_URL=https://host/v1
    ANBU_LLM_MODEL=some-instruct-model
    ANBU_LLM_API_KEY=...            # optional for local servers

Without those variables the analyser runs rules-only, which is the default.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Mapping


class LlmError(RuntimeError):
    """The model pass could not run. Never contains prompt or key material."""


@dataclass(frozen=True)
class LlmConfig:
    base_url: str
    model: str
    api_key: str | None = None
    timeout: float = 60.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "LlmConfig | None":
        values = os.environ if env is None else env
        base = values.get("ANBU_LLM_BASE_URL") or values.get("OPENAI_BASE_URL")
        model = values.get("ANBU_LLM_MODEL") or values.get("OPENAI_MODEL")
        key = values.get("ANBU_LLM_API_KEY") or values.get("OPENAI_API_KEY")
        if not base or not model:
            return None
        return cls(base_url=base.rstrip("/"), model=model, api_key=key or None)


class LlmClient:
    def __init__(self, config: LlmConfig) -> None:
        self.config = config

    def _endpoint(self) -> str:
        if self.config.base_url.endswith("/chat/completions"):
            return self.config.base_url
        return self.config.base_url + "/chat/completions"

    def complete(self, system: str, user: str) -> str:
        body = {
            "model": self.config.model,
            "temperature": 0,
            "max_tokens": 1200,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        request = urllib.request.Request(
            self._endpoint(),
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raise LlmError(f"model server returned HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError):
            raise LlmError("model server was not reachable") from None

        try:
            payload = json.loads(raw)
            content = payload["choices"][0]["message"]["content"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError):
            raise LlmError("model server reply had no readable content") from None
        if not isinstance(content, str) or not content.strip():
            raise LlmError("model server returned an empty reply")
        return content
