"""LLM providers. No SDK: the real provider speaks the OpenAI-compatible chat-completions
HTTP API through the standard library, so CI and the default app need no API key.

Providers only turn (system, user) text into model text. They never see raw events
(the service redacts first) and their output never drives a security decision.
"""

import json
import socket
import urllib.error
import urllib.request
from collections import Counter
from typing import Protocol
from urllib.parse import urlparse

from app.core.config import Settings


class ProviderError(Exception):
    """The provider failed, timed out or returned something unusable (message is safe to
    store: it never contains the API key or the prompt)."""


class Provider(Protocol):
    name: str
    model: str

    def complete(self, system: str, user: str) -> str: ...


class FakeProvider:
    """Deterministic, offline rules over the redacted events, for tests and demos.

    It reads the same prompt a real model would get, so the whole pipeline (redaction,
    prompt, output validation, storage) is exercised.
    """

    name = "fake"
    model = "fake-rules-v1"

    def complete(self, system: str, user: str) -> str:
        data = json.loads(user.split("<data>", 1)[1].rsplit("</data>", 1)[0])
        events = data["events"]
        by_type: dict[str, list[int]] = {}
        for e in events:
            by_type.setdefault(e["event_type"], []).append(e["id"])
        findings = []
        rules = [
            ("auth.login_failed", 5, "high",
             "Repeated failed logins (possible credential stuffing)",
             "Check the source addresses and consider stricter rate limits."),
            ("share.access_denied", 3, "medium",
             "Repeated denied file access (possible IDOR probing)",
             "Review which account is enumerating file ids."),
            ("file.integrity_failure", 1, "high", "Stored file failed an integrity check",
             "Run /verification on the file and inspect the storage for tampering."),
            ("auth.refresh_reuse", 1, "high", "Refresh-token reuse (possible token theft)",
             "The affected sessions were revoked; ask the user to sign in again."),
        ]
        for event_type, threshold, severity, title, recommendation in rules:
            ids = by_type.get(event_type, [])
            if len(ids) >= threshold:
                findings.append({"severity": severity, "title": title,
                                 "evidence_event_ids": ids[:50],
                                 "recommendation": recommendation})
        if data.get("anomalies"):
            findings.append({
                "severity": "medium",
                "title": f"{len(data['anomalies'])} anomalous user-hour(s) flagged by M7",
                "evidence_event_ids": [],
                "recommendation": "Review the flagged hours.",
            })
        counts = Counter(e["event_type"] for e in events)
        breakdown = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
        summary = (f"Analyzed {len(events)} events ({breakdown})." if events
                   else "No events in the selected period.")
        return json.dumps({"summary": summary, "findings": findings})


def _is_local(host: str) -> bool:
    return host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost")


class OpenAICompatibleProvider:
    name = "openai_compatible"

    def __init__(self, settings: Settings) -> None:
        url = urlparse(settings.llm_base_url.rstrip("/"))
        if url.scheme not in ("https", "http") or not url.hostname:
            raise ProviderError("LLM_BASE_URL is not a valid URL")
        if url.scheme == "http" and not _is_local(url.hostname):
            # Never send (even redacted) security data in clear text over a network.
            raise ProviderError("LLM_BASE_URL must use https for non-local hosts")
        if settings.llm_api_key is None or not settings.llm_api_key.get_secret_value():
            raise ProviderError("LLM_API_KEY is not set")
        if not settings.llm_model:
            raise ProviderError("LLM_MODEL is not set")
        self._endpoint = url.geturl() + "/chat/completions"
        self._key = settings.llm_api_key.get_secret_value()
        self._timeout = settings.llm_timeout_seconds
        self.model = settings.llm_model

    def complete(self, system: str, user: str) -> str:
        body = json.dumps({
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }).encode()
        request = urllib.request.Request(  # noqa: S310 - scheme validated in __init__
            self._endpoint, data=body, method="POST",
            headers={"Authorization": f"Bearer {self._key}",
                     "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                payload = json.loads(response.read(2_000_000))
            return payload["choices"][0]["message"]["content"]
        except TimeoutError as exc:
            raise ProviderError(f"provider timed out after {self._timeout:g}s") from exc
        except urllib.error.HTTPError as exc:
            raise ProviderError(f"provider returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError | socket.timeout):
                raise ProviderError(f"provider timed out after {self._timeout:g}s") from exc
            raise ProviderError("provider unreachable") from exc
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderError("provider returned an unexpected response") from exc


def build_provider(settings: Settings) -> Provider | None:
    """None when analysis is disabled."""
    if settings.llm_provider == "fake":
        return FakeProvider()
    if settings.llm_provider == "openai_compatible":
        return OpenAICompatibleProvider(settings)
    return None
