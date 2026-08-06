"""Minimal loopback-only Ollama client."""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class OllamaClient:
    """Call one Ollama server that MUST resolve to IPv4 loopback."""

    origin: str = "http://127.0.0.1:11434"
    timeout_seconds: int = 180

    def __post_init__(self) -> None:
        parsed = urlparse(self.origin)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.path not in {"", "/"}
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Ollama origin must be plain HTTP on 127.0.0.1")

    def request_json(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call one JSON endpoint and return one JSON object."""
        if not path.startswith("/api/"):
            raise ValueError("only Ollama /api/ endpoints are allowed")

        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            f"{self.origin.rstrip('/')}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST" if data is not None else "GET",
        )
        with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
            result = json.load(response)
        if not isinstance(result, dict):
            raise TypeError("Ollama response must be a JSON object")
        return result
