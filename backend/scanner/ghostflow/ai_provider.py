from __future__ import annotations

import abc
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass
class AIProviderResponse:
    content: str
    provider_name: str
    model_name: str
    is_fallback: bool = False
    error: str | None = None


class AIProviderError(Exception):
    """Base exception for AI provider operations."""
    pass


class AIProviderUnavailableError(AIProviderError):
    """Raised when the configured AI provider is unavailable or credentials are missing."""
    pass


class AIProviderRateLimitError(AIProviderError):
    """Raised when the AI provider returns a rate limit (429)."""
    pass


class AIProvider(abc.ABC):
    """Abstract interface for AI Advisory Providers."""

    @abc.abstractmethod
    def generate_advisory(
        self,
        prompt: str,
        system_instruction: str,
        timeout: float = 15.0,
    ) -> AIProviderResponse:
        """Submit evidence prompt to AI model and return raw response content."""
        pass


class DeterministicFallbackProvider(AIProvider):
    """Provides deterministic, evidence-grounded advisory analysis without external network calls.

    Used when AI is disabled, offline, or when upstream providers fail.
    """

    def __init__(self, reason: str = "Deterministic fallback intelligence"):
        self.reason = reason

    def generate_advisory(
        self,
        prompt: str,
        system_instruction: str,
        timeout: float = 15.0,
    ) -> AIProviderResponse:
        # Parse evidence payload embedded in prompt if possible
        try:
            payload = json.loads(prompt)
        except Exception:
            payload = {}

        target_findings = payload.get("findings", [])
        root_cause = payload.get("root_cause")

        finding_rules = [f.get("rule_id", "API") for f in target_findings]
        rule_summary = ", ".join(finding_rules) if finding_rules else "Contract discrepancy"

        confirmed_evidence = []
        for f in target_findings:
            for ev in f.get("evidence", []):
                confirmed_evidence.append(
                    f"{ev.get('role', 'source').capitalize()} evidence in '{ev.get('file')}':{ev.get('line')} - {ev.get('source')}"
                )

        if not confirmed_evidence:
            confirmed_evidence.append("Scanner diagnostic findings and schema contract telemetry.")

        problem_summary = (
            f"API contract discrepancy identified across {len(target_findings)} finding(s): {rule_summary}."
        )
        if root_cause:
            problem_summary += f" Root cause candidate: '{root_cause.get('candidate_id')}'."

        root_cause_explanation = (
            root_cause.get("description", "")
            if root_cause and root_cause.get("description")
            else f"Diagnostic scanner flagged {rule_summary} between client invocation and service definition."
        )

        inferences = [
            f"Aligning client call semantics with backend route declaration will resolve {rule_summary}.",
            "Zero secondary cascading regressions expected if route parameters and methods match.",
        ]

        unknowns = [
            "Runtime traffic volume and production client versioning cannot be determined statically.",
            "Potential out-of-repo external consumers hitting these endpoints are unknown.",
        ]

        fallback_json = {
            "problem_summary": problem_summary,
            "root_cause_explanation": root_cause_explanation,
            "suggested_changes": [
                f"Update frontend client parameters/method to strictly align with backend schema ({rule_summary})."
            ],
            "risks_and_side_effects": [
                "Requires regression verification across all client call sites.",
                "Verify no hardcoded mocks or tests depend on mismatched behavior.",
            ],
            "confidence_score": 0.85,
            "confidence_explanation": "Direct static scanner observation of source code lines and schema definitions.",
            "unsupported_assumptions": [
                "Assumes backend route definition is authoritative over frontend caller."
            ],
            "analysis": {
                "confirmed_evidence": confirmed_evidence,
                "ai_inferences": inferences,
                "unknown_information": unknowns,
            },
            "proposed_files": [],
        }

        return AIProviderResponse(
            content=json.dumps(fallback_json, indent=2),
            provider_name="deterministic_fallback",
            model_name="ghostflow_heuristics_v1",
            is_fallback=True,
        )


class MockAdvisoryProvider(AIProvider):
    """Mock AI Provider for deterministic unit testing."""

    def __init__(
        self,
        canned_response: str | None = None,
        should_fail: bool = False,
        error_type: type[Exception] = AIProviderError,
        error_message: str = "Mock provider failure",
    ):
        self.canned_response = canned_response
        self.should_fail = should_fail
        self.error_type = error_type
        self.error_message = error_message
        self.last_prompt: str | None = None
        self.last_system_instruction: str | None = None

    def generate_advisory(
        self,
        prompt: str,
        system_instruction: str,
        timeout: float = 15.0,
    ) -> AIProviderResponse:
        self.last_prompt = prompt
        self.last_system_instruction = system_instruction

        if self.should_fail:
            raise self.error_type(self.error_message)

        if self.canned_response is not None:
            return AIProviderResponse(
                content=self.canned_response,
                provider_name="mock_provider",
                model_name="mock_model",
                is_fallback=False,
            )

        # Default structured response
        mock_data = {
            "problem_summary": "Mock problem summary",
            "root_cause_explanation": "Mock root cause explanation",
            "suggested_changes": ["Update method in client.ts"],
            "risks_and_side_effects": ["Low risk"],
            "confidence_score": 0.90,
            "confidence_explanation": "Mock confidence",
            "unsupported_assumptions": [],
            "analysis": {
                "confirmed_evidence": ["Evidence 1: client.ts line 10"],
                "ai_inferences": ["Inference 1: Method mismatch"],
                "unknown_information": ["Unknown 1: Production traffic"],
            },
            "proposed_files": [],
        }
        return AIProviderResponse(
            content=json.dumps(mock_data),
            provider_name="mock_provider",
            model_name="mock_model",
            is_fallback=False,
        )


class GeminiAdvisoryProvider(AIProvider):
    """Google Gemini AI Advisory Provider using HTTP REST interface."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        self.model = model or os.environ.get("GHOSTFLOW_GEMINI_MODEL", "gemini-2.5-flash")

    def generate_advisory(
        self,
        prompt: str,
        system_instruction: str,
        timeout: float = 15.0,
    ) -> AIProviderResponse:
        if not self.api_key:
            raise AIProviderUnavailableError("GEMINI_API_KEY is not configured.")

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"

        body = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}],
                }
            ],
            "systemInstruction": {
                "parts": [{"text": system_instruction}],
            },
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                candidates = res_data.get("candidates", [])
                if not candidates:
                    raise AIProviderError("Gemini returned empty candidate list.")
                part = candidates[0].get("content", {}).get("parts", [{}])[0]
                text = part.get("text", "")
                return AIProviderResponse(
                    content=text,
                    provider_name="google_gemini",
                    model_name=self.model,
                    is_fallback=False,
                )
        except urllib.error.HTTPError as err:
            if err.code == 429:
                raise AIProviderRateLimitError(f"Gemini API rate limit exceeded (429): {err.reason}") from err
            elif err.code in (401, 403):
                raise AIProviderUnavailableError(f"Gemini API authentication failed ({err.code}): invalid API key.") from err
            raise AIProviderError(f"Gemini API request failed with HTTP {err.code}: {err.reason}") from err
        except urllib.error.URLError as err:
            raise AIProviderUnavailableError(f"Failed to connect to Gemini API: {err.reason}") from err
        except TimeoutError as err:
            raise AIProviderError(f"Gemini API request timed out after {timeout}s.") from err
        except Exception as exc:
            raise AIProviderError(f"Unexpected error communicating with Gemini API: {exc}") from exc


class OpenAIAdvisoryProvider(AIProvider):
    """OpenAI Advisory Provider using HTTP REST interface."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model or os.environ.get("GHOSTFLOW_OPENAI_MODEL", "gpt-4o-mini")

    def generate_advisory(
        self,
        prompt: str,
        system_instruction: str,
        timeout: float = 15.0,
    ) -> AIProviderResponse:
        if not self.api_key:
            raise AIProviderUnavailableError("OPENAI_API_KEY is not configured.")

        url = "https://api.openai.com/v1/chat/completions"

        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                choices = res_data.get("choices", [])
                if not choices:
                    raise AIProviderError("OpenAI returned empty choice list.")
                text = choices[0].get("message", {}).get("content", "")
                return AIProviderResponse(
                    content=text,
                    provider_name="openai",
                    model_name=self.model,
                    is_fallback=False,
                )
        except urllib.error.HTTPError as err:
            if err.code == 429:
                raise AIProviderRateLimitError(f"OpenAI API rate limit exceeded (429): {err.reason}") from err
            elif err.code in (401, 403):
                raise AIProviderUnavailableError(f"OpenAI API authentication failed ({err.code}): invalid API key.") from err
            raise AIProviderError(f"OpenAI API request failed with HTTP {err.code}: {err.reason}") from err
        except urllib.error.URLError as err:
            raise AIProviderUnavailableError(f"Failed to connect to OpenAI API: {err.reason}") from err
        except TimeoutError as err:
            raise AIProviderError(f"OpenAI API request timed out after {timeout}s.") from err
        except Exception as exc:
            raise AIProviderError(f"Unexpected error communicating with OpenAI API: {exc}") from exc


def get_ai_provider(provider_name: str | None = None, opt_in_external: bool = False) -> AIProvider:
    """Factory to resolve configured AI Advisory Provider.

    Adheres strictly to environment-driven configuration and fails over to deterministic fallback.
    External cloud AI transmission requires explicit developer opt-in or GHOSTFLOW_EXTERNAL_AI_ENABLED=true.
    """
    if os.environ.get("GHOSTFLOW_AI_ENABLED", "true").lower() in ("false", "0", "no"):
        return DeterministicFallbackProvider(reason="AI Advisory explicitly disabled via GHOSTFLOW_AI_ENABLED=false")

    chosen = provider_name or os.environ.get("GHOSTFLOW_AI_PROVIDER", "auto").lower()

    if chosen == "deterministic":
        return DeterministicFallbackProvider()
    elif chosen == "mock":
        return MockAdvisoryProvider()

    # Verify explicit developer opt-in before communicating with external cloud AI
    external_allowed = opt_in_external or os.environ.get("GHOSTFLOW_EXTERNAL_AI_ENABLED", "false").lower() in ("true", "1", "yes")

    if chosen in ("gemini", "openai") and not external_allowed:
        return DeterministicFallbackProvider(
            reason="External AI transmission disabled by default. Explicit developer opt-in required to transmit repository excerpts to cloud AI providers."
        )

    if chosen == "gemini":
        return GeminiAdvisoryProvider()
    elif chosen == "openai":
        return OpenAIAdvisoryProvider()

    # 'auto' mode: check available API keys if external AI is permitted
    if external_allowed:
        if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
            return GeminiAdvisoryProvider()
        elif os.environ.get("OPENAI_API_KEY"):
            return OpenAIAdvisoryProvider()

    # Default safe fallback
    return DeterministicFallbackProvider(reason="External AI is disabled or unconfigured. Using deterministic fallback.")
