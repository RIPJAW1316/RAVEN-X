"""Google Cloud Gemini provider for first-party bundled synthetic Windows demo assessments.

Restricted to the server-owned 'windows-hardening-v1' fixture. Never accepts
arbitrary report facts, live endpoint evidence, or customer data. Uses official
Google Cloud Application Default Credentials (ADC) with per-invocation timeout
bounds and no process-global socket modification. Default-off, bounded timeout,
and no automatic retries.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from ...application.ai.synthetic_demo import (
    CANONICAL_DEMO_GEMINI_ITEMS,
    CANONICAL_DEMO_REFS,
    WINDOWS_HARDENING_DEMO_ID,
)

_PROJECT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


def _validate_project_id(project: str) -> str:
    if not isinstance(project, str) or not project.strip():
        raise ValueError("Google Cloud project ID is missing")
    p = project.strip()
    if not _PROJECT_ID_PATTERN.match(p):
        raise ValueError(f"Invalid Google Cloud project ID '{p}'")
    return p


def _validate_api_key(key: str) -> str:
    if not isinstance(key, str) or not key.strip():
        raise ValueError("Gemini API key is unconfigured")
    k = key.strip()
    # Header safety check: must be printable ASCII without spaces or control characters
    if any(ord(c) < 33 or ord(c) > 126 for c in k):
        raise ValueError("Gemini API key contains unsafe header characters")
    return k


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class CloudGeminiConfig:
    enabled: bool = False
    auth_mode: str = "adc"  # "adc" or "api_key"
    api_key: str = ""
    project: str = ""
    location: str = "global"
    model: str = "gemini-3.5-flash-lite"
    timeout_seconds: int = 15

    def __repr__(self) -> str:
        masked_key = "[REDACTED]" if self.api_key else ""
        return (
            f"CloudGeminiConfig(enabled={self.enabled}, auth_mode={self.auth_mode!r}, "
            f"api_key={masked_key!r}, project={self.project!r}, location={self.location!r}, "
            f"model={self.model!r}, timeout_seconds={self.timeout_seconds})"
        )

    @classmethod
    def from_config(cls, config: Mapping | None = None, *, environ: Mapping | None = None):
        config = config or {}
        ai = config.get("ai", {}) if isinstance(config, Mapping) else {}
        cloud = ai.get("google_cloud", {}) if isinstance(ai, Mapping) else {}
        env = os.environ if environ is None else environ

        enabled_text = str(env.get("RAVENX_CLOUD_GEMINI_ENABLED", cloud.get("enabled", "false"))).lower()
        if enabled_text not in {"true", "false", "1", "0", "yes", "no"}:
            raise ValueError("invalid cloud Gemini enabled flag")

        raw_auth_mode = str(env.get("RAVENX_CLOUD_GEMINI_AUTH_MODE", cloud.get("auth_mode", "adc"))).strip().lower()
        if not raw_auth_mode:
            raw_auth_mode = "adc"
        if raw_auth_mode not in {"adc", "api_key"}:
            raise ValueError(f"invalid cloud Gemini auth_mode '{raw_auth_mode}', expected 'adc' or 'api_key'")

        project = str(env.get("RAVENX_CLOUD_GEMINI_PROJECT", env.get("GOOGLE_CLOUD_PROJECT", cloud.get("project", "")))).strip()
        location = str(env.get("RAVENX_CLOUD_GEMINI_LOCATION", cloud.get("location", cls.location))).strip() or cls.location
        model = str(env.get("RAVENX_CLOUD_GEMINI_MODEL", cloud.get("model", cls.model))).strip() or cls.model
        timeout = int(env.get("RAVENX_CLOUD_GEMINI_TIMEOUT_SECONDS", cloud.get("timeout", cls.timeout_seconds)))

        return cls(
            enabled=enabled_text in {"true", "1", "yes"},
            auth_mode=raw_auth_mode,
            api_key="",
            project=project,
            location=location,
            model=model,
            timeout_seconds=max(1, min(60, timeout)),
        )


class _TimeoutAuthRequest:
    """Wrapper around google.auth.transport.requests.Request enforcing a bounded timeout per call."""

    def __init__(self, timeout_seconds: int = 10, session=None, underlying_request=None):
        self.timeout_seconds = timeout_seconds
        if underlying_request is not None:
            self._request = underlying_request
        else:
            try:
                import google.auth.transport.requests
                self._request = google.auth.transport.requests.Request(session=session)
            except ImportError:
                self._request = None

    def __call__(self, url, method="GET", body=None, headers=None, timeout=None, **kwargs):
        if self._request is None:
            raise RuntimeError("Optional cloud dependency 'google-auth' is required for Google Cloud ADC token exchange")
        effective_timeout = self.timeout_seconds if timeout is None else timeout
        return self._request(url, method=method, body=body, headers=headers, timeout=effective_timeout, **kwargs)


def _get_adc_bearer_token(timeout_seconds: int = 10, request_factory: Callable | None = None) -> str:
    """Acquire OAuth2 bearer token via standard Google ADC with bounded timeout.

    Does not modify process-global socket defaults; enforces timeout on the auth request callable.
    """
    try:
        import google.auth
        import google.auth.transport.requests

        auth_request = request_factory(timeout_seconds) if request_factory else _TimeoutAuthRequest(timeout_seconds=timeout_seconds)
        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
            request=auth_request,
        )
        credentials.refresh(auth_request)
        if not credentials.token:
            raise RuntimeError("ADC credentials refresh did not return a bearer token")
        return credentials.token
    except ImportError:
        raise RuntimeError("Optional cloud dependency 'google-auth' is required for Google Cloud ADC token exchange")


class CloudGeminiProvider:
    """Provider strictly scoped to the server-owned synthetic Windows demo assessment."""

    def __init__(self, config: CloudGeminiConfig, *, transport: Callable | None = None,
                 adc_token_provider: Callable[[], str] | None = None,
                 api_key_provider: Callable[[], str | None] | None = None):
        self.config = config
        self.enabled = config.enabled
        self.model = "gemini-3.5-flash-lite"
        self._transport = transport
        self._adc_token_provider = adc_token_provider
        self._api_key_provider = api_key_provider
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def prioritize_synthetic_demo(self, *, fixture_id: str = WINDOWS_HARDENING_DEMO_ID) -> list[str]:
        """Prioritize synthetic demo findings using Gemini 3.5 Flash-Lite.

        Takes NO user-supplied facts, freeform prompt text, or live endpoint evidence.
        Loads canonical constants strictly from the server-owned synthetic fixture.
        """
        if not self.enabled:
            raise RuntimeError("Gemini cloud demo inference is disabled")
        if fixture_id != WINDOWS_HARDENING_DEMO_ID:
            raise ValueError(f"Cloud Gemini only supports allowlisted demo fixture '{WINDOWS_HARDENING_DEMO_ID}'")

        if self.config.auth_mode == "api_key":
            key_candidate = ""
            if self._api_key_provider is not None:
                key_candidate = self._api_key_provider() or ""
            if not key_candidate and self.config.api_key:
                key_candidate = self.config.api_key
            if not key_candidate:
                try:
                    from ..security.windows_credentials import get_gemini_api_key
                    key_candidate = get_gemini_api_key() or ""
                except Exception:
                    pass
            key = _validate_api_key(key_candidate)
            endpoint_url = (
                f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
            )
            request_headers = {
                "Content-Type": "application/json",
                "x-goog-api-key": key,
            }
            generation_config = {
                "maxOutputTokens": 256,
                "responseMimeType": "application/json",
                "responseJsonSchema": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            }
        elif self.config.auth_mode == "adc":
            # Missing or invalid project fails closed immediately before transport or ADC
            project = _validate_project_id(self.config.project)

            # Pin model and location to verified global Flash-Lite endpoint
            endpoint_url = (
                f"https://aiplatform.googleapis.com/v1/projects/{project}/locations/global/publishers/google/models/{self.model}:generateContent"
            )
            request_headers = {"Content-Type": "application/json"}
            if self._adc_token_provider:
                request_headers["Authorization"] = f"Bearer {self._adc_token_provider()}"
            elif self._transport is None:
                token = _get_adc_bearer_token(timeout_seconds=min(self.config.timeout_seconds, 10))
                request_headers["Authorization"] = f"Bearer {token}"

            generation_config = {
                "maxOutputTokens": 256,
                "responseMimeType": "application/json",
                "responseSchema": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"},
                },
            }
        else:
            raise ValueError(f"Unsupported cloud Gemini auth_mode '{self.config.auth_mode}'")

        findings_payload = [
            {"ref": item["ref"], "severity": item["severity"], "description": item["description"]}
            for item in CANONICAL_DEMO_GEMINI_ITEMS
        ]

        prompt_text = (
            "You are a read-only security analyst. Rank these synthetic Windows findings by remediation priority.\n"
            "Return ONLY a JSON array of the string references ordered from highest to lowest priority.\n"
            "Include every reference exactly once. Do not return Markdown formatting, comments, or explanations.\n"
            f"Findings: {json.dumps(findings_payload, separators=(',', ':'))}"
        )

        # Documented generateContent envelope: omit temperature, explicitly bound output tokens
        request_body = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt_text}],
                }
            ],
            "generationConfig": generation_config,
        }
        serialized_body = json.dumps(request_body, ensure_ascii=True).encode("utf-8")

        if self._transport is not None:
            raw_response = self._transport(
                url=endpoint_url,
                headers=request_headers,
                body=serialized_body,
            )
        else:
            req = Request(
                endpoint_url,
                data=serialized_body,
                headers=request_headers,
                method="POST",
            )
            try:
                with self._opener.open(req, timeout=self.config.timeout_seconds) as resp:
                    if resp.status != 200:
                        raise RuntimeError(f"Cloud Gemini provider returned HTTP {resp.status}")
                    raw_response = resp.read(65537)
            except (HTTPError, URLError, TimeoutError, OSError) as err:
                raise RuntimeError("Cloud Gemini provider unavailable") from err

        if len(raw_response) > 65536:
            raise RuntimeError("Cloud Gemini response exceeds bound")

        return self._parse_and_validate_permutation(raw_response)

    def _parse_and_validate_permutation(self, raw_bytes: bytes | str) -> list[str]:
        """Parse documented Google generateContent response and validate complete permutation."""
        try:
            data = json.loads(raw_bytes if isinstance(raw_bytes, str) else raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as err:
            raise ValueError("invalid JSON from Cloud Gemini") from err

        if not isinstance(data, dict):
            raise ValueError("Cloud Gemini response is not a JSON object")

        candidates = data.get("candidates")
        if not isinstance(candidates, list) or len(candidates) != 1:
            raise ValueError("Cloud Gemini response must contain exactly one candidate")

        cand = candidates[0]
        if not isinstance(cand, dict):
            raise ValueError("Cloud Gemini candidate is not a JSON object")

        finish_reason = cand.get("finishReason")
        if finish_reason != "STOP":
            raise ValueError(f"Cloud Gemini candidate finishReason is '{finish_reason}', expected 'STOP'")

        parts = cand.get("content", {}).get("parts")
        if not isinstance(parts, list) or not parts:
            raise ValueError("Cloud Gemini candidate missing content parts")

        text = parts[0].get("text")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("Cloud Gemini candidate content text is empty")

        try:
            parsed = json.loads(text.strip())
        except Exception as err:
            raise ValueError("Cloud Gemini output is not a valid JSON array") from err

        return self._validate_complete_permutation(parsed)

    def _validate_complete_permutation(self, refs: Any) -> list[str]:
        if not isinstance(refs, list):
            raise ValueError("output is not a JSON list")
        if not all(isinstance(r, str) for r in refs):
            raise ValueError("output items must all be strings")
        if len(refs) != len(CANONICAL_DEMO_REFS):
            raise ValueError("Cloud model returned incomplete permutation")
        if len(refs) != len(set(refs)):
            raise ValueError("Cloud model returned duplicate references")
        if set(refs) != set(CANONICAL_DEMO_REFS):
            raise ValueError("Cloud model returned unknown or invented references")
        return refs
