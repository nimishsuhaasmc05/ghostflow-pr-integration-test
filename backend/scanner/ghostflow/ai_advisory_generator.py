from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Finding
from .repair import validate_safe_path
from .repair_models import IntelligentRepairProposal
from .ai_provider import (
    AIProvider,
    AIProviderError,
    DeterministicFallbackProvider,
    get_ai_provider,
)
from .ai_prompt import build_advisory_prompt
from .ai_safety_filter import AISafetyFilter
from .proposal_store import ServerProposalStore


class AIAdvisoryGenerationError(Exception):
    """Raised when AI advisory proposal generation cannot proceed."""
    pass


def generate_ai_advisory_proposal(
    project_root: Path,
    target_id: str,
    findings: list[Finding],
    root_causes: list[dict[str, Any]] | None = None,
    allowed_roots: list[Path] | None = None,
    provider: AIProvider | None = None,
    opt_in_external: bool = False,
) -> IntelligentRepairProposal:
    """Generate an evidence-grounded AI advisory repair proposal.

    Zero source files are modified. All changes pass through deterministic safety filtering.
    """
    canonical_root = project_root.expanduser().resolve()

    # 1. Resolve target findings & root cause
    matched_rc = None
    target_findings: list[Finding] = []

    if root_causes:
        for rc in root_causes:
            if rc.get("candidate_id") == target_id or rc.get("id") == target_id:
                matched_rc = rc
                break

    if matched_rc:
        rc_finding_ids = set(matched_rc.get("finding_ids", []))
        target_findings = [f for f in findings if f.id in rc_finding_ids]
        if not target_findings:
            raise AIAdvisoryGenerationError(
                f"Root cause '{target_id}' specifies findings {rc_finding_ids}, but none were found in scan findings."
            )
    else:
        single = next((f for f in findings if f.id == target_id), None)
        if single:
            target_findings = [single]
        else:
            raise AIAdvisoryGenerationError(
                f"Target '{target_id}' not found in scan findings or root cause candidates."
            )

    # 2. Build evidence prompt with untrusted data isolation
    prompt, system_inst = build_advisory_prompt(target_findings, matched_rc)

    # 3. Invoke provider with graceful deterministic fallback
    active_provider = provider or get_ai_provider(opt_in_external=opt_in_external)
    raw_ai_dict: dict[str, Any] = {}

    try:
        response = active_provider.generate_advisory(prompt, system_inst)
        # Parse JSON output
        cleaned_content = response.content.strip()
        # Strip potential markdown fences if returned
        if cleaned_content.startswith("```json"):
            cleaned_content = cleaned_content[7:]
        elif cleaned_content.startswith("```"):
            cleaned_content = cleaned_content[3:]
        if cleaned_content.endswith("```"):
            cleaned_content = cleaned_content[:-3]
        cleaned_content = cleaned_content.strip()

        raw_ai_dict = json.loads(cleaned_content)
    except (AIProviderError, json.JSONDecodeError, Exception) as exc:
        # Fall back to deterministic provider on upstream failure
        fallback = DeterministicFallbackProvider(reason=f"Provider fallback due to: {exc}")
        fb_resp = fallback.generate_advisory(prompt, system_inst)
        raw_ai_dict = json.loads(fb_resp.content)

    # 4. Pass through deterministic safety filter
    proposal = AISafetyFilter.validate_and_construct(
        project_root=canonical_root,
        raw_ai_data=raw_ai_dict,
        target_findings=target_findings,
        root_cause=matched_rc,
        allowed_roots=allowed_roots,
    )

    # 5. Persist server-side in ServerProposalStore with HMAC signing
    ServerProposalStore.save_proposal(canonical_root, proposal, allowed_roots=allowed_roots)
    return proposal
