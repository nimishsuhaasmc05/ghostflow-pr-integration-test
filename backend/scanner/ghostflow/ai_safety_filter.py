from __future__ import annotations

import difflib
import hashlib
import re
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from .models import Finding
from .repair import validate_safe_path, SAFE_AUTOFIX_RULES
from .repair_models import (
    AIAdvisoryMetadata,
    IntelligentRepairProposal,
    PatchHunk,
    ProposalApprovalState,
    ProposalFile,
    ProposalOrigin,
    ProposalVerificationPlan,
    TripartiteAnalysis,
)
from .proposal_store import ServerProposalStore
from .syntax_validator import validate_file_syntax


class AISafetyViolationError(Exception):
    """Raised when an AI-generated proposal violates critical deterministic safety invariants."""
    pass


class AISafetyFilter:
    """Enforces strict deterministic safety validation on untrusted AI outputs before persistence."""

    DANGEROUS_PATTERNS = [
        re.compile(r"\b(?:rm|del|rmdir)\s+-[a-zA-Z]*[rf]", re.IGNORECASE),
        re.compile(r"\b(?:curl|wget)\s+[^\n|]+\|\s*(?:bash|sh|cmd|powershell)", re.IGNORECASE),
        re.compile(r"\b(?:child_process\.(?:exec|spawn)|subprocess\.(?:Popen|run|call)|os\.system)\b"),
        re.compile(r"\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?)\s+-[a-zA-Z]*[eEcC]", re.IGNORECASE),
        re.compile(r"\bsh\s+-c\b", re.IGNORECASE),
    ]

    @classmethod
    def validate_and_construct(
        cls,
        project_root: Path,
        raw_ai_data: dict[str, Any],
        target_findings: list[Finding],
        root_cause: dict[str, Any] | None = None,
        allowed_roots: list[Path] | None = None,
    ) -> IntelligentRepairProposal:
        canonical_root = project_root.expanduser().resolve()

        # 1. Collect legitimate evidence-referenced files
        evidence_files: set[str] = set()
        for f in target_findings:
            for ev in f.evidence:
                if ev.file:
                    evidence_files.add(ev.file.replace("\\", "/"))

        if root_cause:
            for comp in root_cause.get("affected_components", []):
                evidence_files.add(comp.replace("\\", "/"))

        # 2. Extract and sanitize advisory metadata
        problem_summary = str(raw_ai_data.get("problem_summary", "AI advisory analysis")).strip()
        root_cause_explanation = str(raw_ai_data.get("root_cause_explanation", "")).strip()
        suggested_changes = [str(c) for c in raw_ai_data.get("suggested_changes", []) if isinstance(c, str)]
        risks_and_side_effects = [str(r) for r in raw_ai_data.get("risks_and_side_effects", []) if isinstance(r, str)]
        confidence_explanation = str(raw_ai_data.get("confidence_explanation", "")).strip()
        unsupported_assumptions = [str(a) for a in raw_ai_data.get("unsupported_assumptions", []) if isinstance(a, str)]

        # Raw confidence score clamped to [0.0, 0.95] (AI advisory never claims 1.0 absolute certainty)
        try:
            raw_conf = float(raw_ai_data.get("confidence_score", 0.8))
            confidence_score = max(0.0, min(0.95, raw_conf))
        except (ValueError, TypeError):
            confidence_score = 0.8

        analysis_dict = raw_ai_data.get("analysis", {})
        tripartite = TripartiteAnalysis(
            confirmed_evidence=[str(e) for e in analysis_dict.get("confirmed_evidence", []) if isinstance(e, str)],
            ai_inferences=[str(i) for i in analysis_dict.get("ai_inferences", []) if isinstance(i, str)],
            unknown_information=[str(u) for u in analysis_dict.get("unknown_information", []) if isinstance(u, str)],
        )

        # 3. Process and validate proposed hunks (if any)
        affected_files: list[ProposalFile] = []
        raw_files = raw_ai_data.get("proposed_files", [])
        downgraded_reasons: list[str] = []

        if isinstance(raw_files, list):
            for pf in raw_files:
                if not isinstance(pf, dict):
                    continue
                rel_path = str(pf.get("rel_path", "")).strip().replace("\\", "/")
                if not rel_path:
                    continue

                # Safety Check: Target file must belong to verified evidence
                if rel_path not in evidence_files:
                    downgraded_reasons.append(
                        f"AI attempted to modify unreferenced file '{rel_path}' not present in scanner evidence."
                    )
                    continue

                # Safety Check: Path containment
                try:
                    abs_path = validate_safe_path(rel_path, canonical_root, allowed_roots)
                except Exception as err:
                    downgraded_reasons.append(f"Invalid path traversal on '{rel_path}': {err}")
                    continue

                if not abs_path.is_file():
                    downgraded_reasons.append(f"AI targeted non-existent file on disk: '{rel_path}'.")
                    continue

                original_bytes = abs_path.read_bytes()
                orig_sha = hashlib.sha256(original_bytes).hexdigest()
                orig_text = original_bytes.decode("utf-8", errors="replace")
                orig_lines = orig_text.splitlines(keepends=True)

                raw_hunks = pf.get("hunks", [])
                if not isinstance(raw_hunks, list) or not raw_hunks:
                    continue

                valid_hunks: list[PatchHunk] = []
                file_invalid = False

                for h in raw_hunks:
                    if not isinstance(h, dict):
                        continue

                    start_l = int(h.get("start_line", 0))
                    end_l = int(h.get("end_line", 0))
                    orig_exc = str(h.get("original_excerpt", ""))
                    repl_content = str(h.get("replacement_content", ""))
                    expl = str(h.get("explanation", ""))

                    # Safety Check: Execution or command injection
                    for pat in cls.DANGEROUS_PATTERNS:
                        if pat.search(repl_content):
                            downgraded_reasons.append(
                                f"Dangerous execution instruction rejected in proposal for '{rel_path}'."
                            )
                            file_invalid = True
                            break

                    if file_invalid:
                        break

                    # Bounds check
                    if start_l < 1 or end_l < start_l or start_l > len(orig_lines) + 1:
                        downgraded_reasons.append(
                            f"Out-of-bounds line range [{start_l}, {end_l}] for '{rel_path}' ({len(orig_lines)} lines)."
                        )
                        file_invalid = True
                        break

                    # Excerpt check against actual disk lines
                    actual_excerpt = "".join(orig_lines[start_l - 1 : end_l])
                    # If AI provided an excerpt, check compatibility
                    if orig_exc and orig_exc.strip() != actual_excerpt.strip():
                        downgraded_reasons.append(
                            f"Source excerpt mismatch at line {start_l} in '{rel_path}'."
                        )
                        file_invalid = True
                        break

                    h_id = f"hunk_ai_{uuid.uuid4().hex[:8]}"
                    excerpt_sha = hashlib.sha256(actual_excerpt.encode("utf-8")).hexdigest()
                    valid_hunks.append(
                        PatchHunk(
                            hunk_id=h_id,
                            start_line=start_l,
                            end_line=end_l,
                            original_excerpt=actual_excerpt,
                            replacement_content=repl_content,
                            excerpt_sha256=excerpt_sha,
                            explanation=expl,
                        )
                    )

                if file_invalid or not valid_hunks:
                    continue

                # Sort hunks by line
                sorted_hunks = sorted(valid_hunks, key=lambda hk: hk.start_line)
                has_overlap = False
                for i in range(len(sorted_hunks) - 1):
                    if sorted_hunks[i].end_line >= sorted_hunks[i + 1].start_line:
                        downgraded_reasons.append(f"Overlapping hunks in '{rel_path}'.")
                        has_overlap = True
                        break

                if has_overlap:
                    continue

                # Apply in memory to test syntax
                mod_lines = list(orig_lines)
                for hk in reversed(sorted_hunks):
                    s_idx = hk.start_line - 1
                    e_idx = hk.end_line
                    rep_lines = hk.replacement_content.splitlines(keepends=True)
                    mod_lines[s_idx:e_idx] = rep_lines

                mod_text = "".join(mod_lines)
                syntax_res = validate_file_syntax(abs_path, mod_text, canonical_root)
                if not syntax_res.valid:
                    downgraded_reasons.append(
                        f"Syntax validation failed on '{rel_path}': {syntax_res.error_message}"
                    )
                    continue

                diff = list(
                    difflib.unified_diff(
                        orig_lines,
                        mod_lines,
                        fromfile=f"a/{rel_path}",
                        tofile=f"b/{rel_path}",
                        lineterm="",
                    )
                )

                affected_files.append(
                    ProposalFile(
                        rel_path=rel_path,
                        original_file_sha256=orig_sha,
                        replacement_file_sha256=hashlib.sha256(mod_text.encode("utf-8")).hexdigest(),
                        hunks=sorted_hunks,
                        diff="".join(diff),
                        language=syntax_res.language,
                    )
                )

        # 4. If any hunks failed validation, append explanation to limitations
        if downgraded_reasons:
            risks_and_side_effects.append(
                f"Safety filter rejected {len(downgraded_reasons)} proposed change(s): {'; '.join(downgraded_reasons)}."
            )
            unsupported_assumptions.append(
                "Some AI-generated hunk suggestions were invalidated by deterministic safety rules."
            )

        now_dt = datetime.now(timezone.utc)
        proposal_id = ServerProposalStore.generate_proposal_id()
        created_at = now_dt.isoformat()
        expires_at = (now_dt + timedelta(hours=1)).isoformat()

        target_ids = [f.id for f in target_findings]
        v_plan = ProposalVerificationPlan(
            target_finding_ids=target_ids,
            expected_resolved_findings=target_ids,
            prohibited_new_findings=[],
            syntax_validation_targets=[f.rel_path for f in affected_files],
            strategy="AI Advisory: Post-review verification scan requiring developer approval.",
        )

        ai_meta = AIAdvisoryMetadata(
            problem_summary=problem_summary,
            root_cause_explanation=root_cause_explanation,
            suggested_changes=suggested_changes,
            risks_and_side_effects=risks_and_side_effects,
            confidence_score=confidence_score,
            confidence_explanation=confidence_explanation,
            unsupported_assumptions=unsupported_assumptions,
            analysis=tripartite,
        )

        # Invariants: origin MUST be AI_ADVISORY, can_autofix MUST be False!
        proposal = IntelligentRepairProposal(
            proposal_id=proposal_id,
            canonical_project_root=str(canonical_root),
            created_at=created_at,
            expires_at=expires_at,
            root_cause_id=root_cause.get("candidate_id") or root_cause.get("id") if root_cause else None,
            target_finding_ids=target_ids,
            affected_files=affected_files,
            summary=f"AI Advisory Proposal: {problem_summary}",
            detailed_explanation=root_cause_explanation,
            expected_result="Developer-guided alignment and resolution of contract mismatch.",
            risks_and_limitations=risks_and_side_effects,
            verification_plan=v_plan,
            proposal_origin=ProposalOrigin.AI_ADVISORY,
            can_autofix=False,  # STRICT INVARIANT: AI proposals are NEVER autofixable
            approval_state=ProposalApprovalState.PENDING_REVIEW,
            ai_advisory=ai_meta,
        )

        return proposal
