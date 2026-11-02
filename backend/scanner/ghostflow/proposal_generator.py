from __future__ import annotations

import difflib
import hashlib
import io
import re
import tokenize
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from .models import Finding, Evidence
from .repair import SAFE_AUTOFIX_RULES, validate_safe_path, explain_finding
from .compatibility import map_py_to_ts
from .repair_models import (
    IntelligentRepairProposal,
    PatchHunk,
    ProposalApprovalState,
    ProposalFile,
    ProposalOrigin,
    ProposalVerificationPlan,
)
from .proposal_store import ServerProposalStore
from .syntax_validator import validate_file_syntax


class ProposalGenerationError(Exception):
    """Base exception for proposal generation failures."""
    pass


class UnsupportedRepairRuleError(ProposalGenerationError):
    """Raised when an unsupported diagnostic rule is requested for repair."""
    pass


class InsufficientEvidenceError(ProposalGenerationError):
    """Raised when finding evidence is insufficient to locate and construct a deterministic fix."""
    pass


def classify_jsts_code(source: str) -> list[bool]:
    """Return a boolean mask where True indicates executable code tokens.

    False indicates comments (inline // or block /* */), string literals ("" or ''),
    or template literal contents (``).
    """
    n = len(source)
    is_code = [True] * n
    i = 0
    state = "CODE"

    while i < n:
        c = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if state == "CODE":
            if c == "/" and nxt == "/":
                is_code[i] = False
                is_code[i + 1] = False
                state = "LINE_COMMENT"
                i += 2
                continue
            elif c == "/" and nxt == "*":
                is_code[i] = False
                is_code[i + 1] = False
                state = "BLOCK_COMMENT"
                i += 2
                continue
            elif c == "'":
                is_code[i] = False
                state = "STRING_S"
                i += 1
                continue
            elif c == '"':
                is_code[i] = False
                state = "STRING_D"
                i += 1
                continue
            elif c == "`":
                is_code[i] = False
                state = "TEMPLATE"
                i += 1
                continue
            else:
                is_code[i] = True
                i += 1
                continue

        elif state == "LINE_COMMENT":
            is_code[i] = False
            if c == "\n":
                state = "CODE"
            i += 1

        elif state == "BLOCK_COMMENT":
            is_code[i] = False
            if c == "*" and nxt == "/":
                if i + 1 < n:
                    is_code[i + 1] = False
                state = "CODE"
                i += 2
                continue
            i += 1

        elif state == "STRING_S":
            is_code[i] = False
            if c == "\\":
                if i + 1 < n:
                    is_code[i + 1] = False
                i += 2
                continue
            elif c == "'":
                state = "CODE"
            i += 1

        elif state == "STRING_D":
            is_code[i] = False
            if c == "\\":
                if i + 1 < n:
                    is_code[i + 1] = False
                i += 2
                continue
            elif c == '"':
                state = "CODE"
            i += 1

        elif state == "TEMPLATE":
            is_code[i] = False
            if c == "\\":
                if i + 1 < n:
                    is_code[i + 1] = False
                i += 2
                continue
            elif c == "`":
                state = "CODE"
            i += 1

    return is_code


def classify_python_code(source: str) -> list[bool]:
    """Return a boolean mask where True indicates executable code in Python."""
    n = len(source)
    is_code = [True] * n
    try:
        tokens = tokenize.tokenize(io.BytesIO(source.encode("utf-8")).readline)
        lines = source.splitlines(keepends=True)
        line_offsets = [0]
        for l in lines:
            line_offsets.append(line_offsets[-1] + len(l))

        for tok in tokens:
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                sline, scol = tok.start
                eline, ecol = tok.end
                start_char = line_offsets[sline - 1] + scol
                end_char = line_offsets[eline - 1] + ecol
                for pos in range(start_char, min(end_char, n)):
                    is_code[pos] = False
    except Exception:
        pass
    return is_code


def _generate_unified_diff(original_text: str, modified_text: str, rel_path: str) -> str:
    """Generate git-compatible unified diff."""
    norm_path = rel_path.replace("\\", "/")
    orig_lines = original_text.splitlines(keepends=True)
    mod_lines = modified_text.splitlines(keepends=True)
    diff = list(
        difflib.unified_diff(
            orig_lines,
            mod_lines,
            fromfile=f"a/{norm_path}",
            tofile=f"b/{norm_path}",
            lineterm="",
        )
    )
    return "".join(diff)


def _generate_hunk_for_finding(
    finding: Finding,
    canonical_root: Path,
    allowed_roots: list[Path] | None = None,
) -> tuple[str, PatchHunk]:
    """Generate a single PatchHunk for a supported finding (API002, API003, API004).

    Returns (rel_path, PatchHunk).
    """
    if finding.rule_id not in SAFE_AUTOFIX_RULES:
        raise UnsupportedRepairRuleError(
            f"Rule '{finding.rule_id}' is not in SAFE_AUTOFIX_RULES and cannot be repaired deterministically."
        )

    fe_ev = next((e for e in finding.evidence if e.role == "frontend"), None)
    be_ev = next((e for e in finding.evidence if e.role == "backend"), None)

    if not fe_ev or not fe_ev.file:
        raise InsufficientEvidenceError(
            f"Finding '{finding.id}' ({finding.rule_id}) lacks frontend source evidence file."
        )

    abs_path = validate_safe_path(fe_ev.file, canonical_root, allowed_roots)
    if not abs_path.is_file():
        raise InsufficientEvidenceError(
            f"Target file for finding '{finding.id}' does not exist on disk: '{fe_ev.file}'."
        )

    file_text = abs_path.read_text(encoding="utf-8")
    file_lines = file_text.splitlines(keepends=True)
    details = finding.details or {}

    original_code = ""
    replacement_code = ""
    start_line = 0
    end_line = 0
    hunk_explanation = ""

    # -------------------------------------------------------------
    # API002: HTTP Method Mismatch
    # -------------------------------------------------------------
    if finding.rule_id == "API002":
        target_method = None
        if be_ev and be_ev.source:
            # Verify backend evidence is not commented out or inside multiline docstrings
            is_valid_be_source = True
            if be_ev.file and be_ev.file.endswith(".py"):
                try:
                    be_abs = validate_safe_path(be_ev.file, canonical_root, allowed_roots)
                    if be_abs.is_file():
                        be_text = be_abs.read_text(encoding="utf-8")
                        be_code_mask = classify_python_code(be_text)
                        be_lines = be_text.splitlines(keepends=True)
                        be_starts = [0]
                        for bl in be_lines:
                            be_starts.append(be_starts[-1] + len(bl))
                        be_line_idx = max(0, (be_ev.line or 1) - 1)
                        if be_line_idx < len(be_lines):
                            pos = be_starts[be_line_idx]
                            m_be = re.search(r"@(?:app|router|[A-Za-z0-9_]+)\.(get|post|put|patch|delete)", be_lines[be_line_idx], re.IGNORECASE)
                            if m_be and not be_code_mask[pos + m_be.start()]:
                                is_valid_be_source = False
                except Exception:
                    pass

            if is_valid_be_source:
                m = re.search(r"(?:@|\b)(?:app|router|[A-Za-z0-9_]+)\.(get|post|put|patch|delete)", be_ev.source, re.IGNORECASE)
                if m:
                    target_method = m.group(1).upper()

        if not target_method:
            backend_methods = details.get("backend_methods", [])
            if len(backend_methods) == 1:
                target_method = backend_methods[0].upper()
            elif len(backend_methods) > 1:
                raise InsufficientEvidenceError(
                    f"Finding '{finding.id}' has ambiguous backend methods ({backend_methods}); cannot determine correct method safely."
                )

        if not target_method:
            raise InsufficientEvidenceError(
                f"Finding '{finding.id}' lacks backend declared method evidence to correct frontend call."
            )

        # Build lexical code mask for frontend file
        is_code = classify_jsts_code(file_text)
        line_starts = [0]
        for l in file_lines:
            line_starts.append(line_starts[-1] + len(l))

        target_line_idx = max(0, (fe_ev.line or 1) - 1)
        found_idx = None

        for idx in range(max(0, target_line_idx - 2), min(len(file_lines), target_line_idx + 8)):
            line_str = file_lines[idx]
            line_pos = line_starts[idx]

            # Find all potential matches on this line
            m_method = [
                m for m in re.finditer(r"\bmethod\s*:\s*['\"][A-Z]+['\"]", line_str)
                if (line_pos + m.start() < len(is_code)) and is_code[line_pos + m.start()]
            ]
            m_axios = [
                m for m in re.finditer(r"\baxios\.[a-z]+", line_str)
                if (line_pos + m.start() < len(is_code)) and is_code[line_pos + m.start()]
            ]

            valid_matches = m_method + m_axios
            if len(valid_matches) > 1:
                raise InsufficientEvidenceError(
                    f"Multiple executable HTTP method calls detected on line {idx + 1} in '{fe_ev.file}'; "
                    "cannot safely disambiguate which call to patch without guessing."
                )
            elif len(valid_matches) == 1:
                found_idx = idx
                break

        if found_idx is None:
            raise InsufficientEvidenceError(
                f"Could not locate executable HTTP method declaration around line {fe_ev.line} in '{fe_ev.file}'."
            )

        original_line = file_lines[found_idx]

        # Check if code is already aligned with target method
        if (
            re.search(rf"\bmethod\s*:\s*['\"]{re.escape(target_method)}['\"]", original_line, re.IGNORECASE)
            or re.search(rf"\baxios\.{re.escape(target_method.lower())}\b", original_line)
        ):
            raise InsufficientEvidenceError(
                f"HTTP method in '{fe_ev.file}' line {found_idx + 1} is already aligned with '{target_method}'."
            )

        repl_line = re.sub(r"\bmethod\s*:\s*['\"][A-Z]+['\"]", f"method: '{target_method}'", original_line)
        repl_line = re.sub(r"\baxios\.[a-z]+", f"axios.{target_method.lower()}", repl_line)

        if repl_line == original_line:
            raise InsufficientEvidenceError(
                f"Failed to generate replacement method '{target_method}' for line {found_idx + 1}."
            )

        original_code = original_line
        replacement_code = repl_line
        start_line = found_idx + 1
        end_line = found_idx + 1
        hunk_explanation = f"Update frontend HTTP method to '{target_method}' to align with backend route."

    # -------------------------------------------------------------
    # API003: Path Parameter Name Mismatch
    # -------------------------------------------------------------
    elif finding.rule_id == "API003":
        fe_params = details.get("frontend_params", [])
        be_params = details.get("backend_params", [])
        if not fe_params or not be_params:
            raise InsufficientEvidenceError(
                f"Finding '{finding.id}' is missing frontend or backend parameter name details."
            )

        if len(fe_params) != 1 or len(be_params) != 1:
            raise InsufficientEvidenceError(
                f"Finding '{finding.id}' has ambiguous parameter mismatch: frontend {fe_params}, backend {be_params}."
            )

        fe_name = fe_params[0]
        be_name = be_params[0]

        # Validate identifiers to prevent syntax injection or invalid replacements
        id_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
        if not id_re.match(fe_name) or not id_re.match(be_name):
            raise InsufficientEvidenceError(
                f"Invalid parameter identifier: frontend '{fe_name}', backend '{be_name}'."
            )

        # Check if already aligned
        if fe_name == be_name:
            raise InsufficientEvidenceError(
                f"Frontend parameter '{fe_name}' is already identical to backend parameter '{be_name}'."
            )

        target_line_idx = max(0, (fe_ev.line or 1) - 1)

        # Enclosing function scan
        func_start_idx = target_line_idx
        for idx in range(target_line_idx, max(-1, target_line_idx - 6), -1):
            line_str = file_lines[idx].strip()
            if line_str.startswith(("//", "/*", "*", "#")):
                continue
            if re.search(rf"\b(function\s+\w+|\w+\s*=\s*(?:async\s*)?\([^)]*\))\s*", file_lines[idx]):
                func_start_idx = idx
                break

        func_end_idx = target_line_idx
        for idx in range(target_line_idx, min(len(file_lines), target_line_idx + 6)):
            if "}" in file_lines[idx] or ");" in file_lines[idx]:
                func_end_idx = idx
                break

        excerpt_lines = file_lines[func_start_idx : func_end_idx + 1]
        original_code = "".join(excerpt_lines)

        # Filter out comments from replacement targeting
        repl = original_code
        repl = re.sub(rf"\$\{{\s*{re.escape(fe_name)}\s*\}}", f"${{{be_name}}}", repl)
        repl = re.sub(rf"\b{re.escape(fe_name)}(?=\s*[:,\)])", be_name, repl)

        if repl == original_code:
            raise InsufficientEvidenceError(
                f"Could not locate parameter '{fe_name}' to rename to '{be_name}' in '{fe_ev.file}'."
            )

        replacement_code = repl
        start_line = func_start_idx + 1
        end_line = func_end_idx + 1
        hunk_explanation = f"Rename parameter '{fe_name}' to '{be_name}' to match backend path parameter."

    # -------------------------------------------------------------
    # API004: Path Parameter Type Mismatch
    # -------------------------------------------------------------
    elif finding.rule_id == "API004":
        param = details.get("parameter", "")
        be_type = details.get("backend_type", "")
        ts_type = map_py_to_ts(be_type)
        if not param or not ts_type:
            raise InsufficientEvidenceError(
                f"Finding '{finding.id}' is missing parameter or backend type details."
            )

        is_code = classify_jsts_code(file_text)
        line_starts = [0]
        for l in file_lines:
            line_starts.append(line_starts[-1] + len(l))

        target_line_idx = max(0, (fe_ev.line or 1) - 1)
        found_idx = None
        for idx in range(target_line_idx, max(-1, target_line_idx - 6), -1):
            line_str = file_lines[idx]
            line_pos = line_starts[idx]
            matches = [
                m for m in re.finditer(rf"\b{re.escape(param)}\s*:\s*[A-Za-z0-9_]+", line_str)
                if (line_pos + m.start() < len(is_code)) and is_code[line_pos + m.start()]
            ]
            if len(matches) > 1:
                raise InsufficientEvidenceError(
                    f"Multiple executable type annotations for parameter '{param}' detected on line {idx + 1}; ambiguous target."
                )
            elif len(matches) == 1:
                found_idx = idx
                break

        if found_idx is None:
            raise InsufficientEvidenceError(
                f"Could not locate type annotation for parameter '{param}' in '{fe_ev.file}'."
            )

        original_line = file_lines[found_idx]

        # Check if already aligned with target type
        if re.search(rf"\b{re.escape(param)}\s*:\s*{re.escape(ts_type)}\b", original_line):
            raise InsufficientEvidenceError(
                f"Parameter '{param}' in '{fe_ev.file}' line {found_idx + 1} is already typed as '{ts_type}'."
            )

        repl_line = re.sub(
            rf"(\b{re.escape(param)}\s*:\s*)[A-Za-z0-9_]+",
            rf"\g<1>{ts_type}",
            original_line,
        )

        if repl_line == original_line:
            raise InsufficientEvidenceError(
                f"Failed to update parameter '{param}' type to '{ts_type}'."
            )

        original_code = original_line
        replacement_code = repl_line
        start_line = found_idx + 1
        end_line = found_idx + 1
        hunk_explanation = f"Update parameter '{param}' type to '{ts_type}' to align with backend schema."

    hunk_id = f"hunk_{uuid.uuid4().hex[:8]}"
    excerpt_sha = hashlib.sha256(original_code.encode("utf-8")).hexdigest()

    hunk = PatchHunk(
        hunk_id=hunk_id,
        start_line=start_line,
        end_line=end_line,
        original_excerpt=original_code,
        replacement_content=replacement_code,
        excerpt_sha256=excerpt_sha,
        explanation=hunk_explanation,
    )
    return fe_ev.file, hunk


def generate_deterministic_proposal(
    project_root: Path,
    target_id: str,
    findings: list[Finding],
    root_causes: list[dict[str, Any]] | None = None,
    allowed_roots: list[Path] | None = None,
) -> IntelligentRepairProposal:
    """Generate an evidence-driven, multi-file deterministic repair proposal for a finding or root cause.

    Persists the proposal server-side in ServerProposalStore and returns it for developer review.
    Zero project files are modified.
    """
    canonical_root = project_root.expanduser().resolve()

    # 1. Identify target findings
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
            raise ProposalGenerationError(
                f"Root cause '{target_id}' specifies finding IDs {rc_finding_ids}, but none were found in scan findings."
            )
    else:
        # Check single finding
        single = next((f for f in findings if f.id == target_id), None)
        if single:
            target_findings = [single]
        else:
            raise ProposalGenerationError(
                f"Target '{target_id}' was not found in findings or root cause candidates."
            )

    # 2. Check all target findings are in SAFE_AUTOFIX_RULES
    unsupported = [f for f in target_findings if f.rule_id not in SAFE_AUTOFIX_RULES]
    if unsupported:
        unsupported_rules = sorted({f.rule_id for f in unsupported})
        raise UnsupportedRepairRuleError(
            f"Cannot generate automated repair: target includes unsupported rule(s): {', '.join(unsupported_rules)}. "
            f"Only rules in SAFE_AUTOFIX_RULES ({', '.join(sorted(SAFE_AUTOFIX_RULES))}) are eligible."
        )

    # 3. Generate hunks grouped by file
    hunks_by_file: dict[str, list[PatchHunk]] = {}

    for finding in target_findings:
        rel_file, hunk = _generate_hunk_for_finding(finding, canonical_root, allowed_roots)
        hunks_by_file.setdefault(rel_file, []).append(hunk)

    # 4. Construct ProposalFile objects with syntax checking and diffs
    affected_files: list[ProposalFile] = []

    for rel_path, hunks in hunks_by_file.items():
        abs_path = validate_safe_path(rel_path, canonical_root, allowed_roots)
        original_bytes = abs_path.read_bytes()
        orig_sha = hashlib.sha256(original_bytes).hexdigest()
        orig_text = original_bytes.decode("utf-8")
        orig_lines = orig_text.splitlines(keepends=True)

        # Sort hunks by line and assert non-overlapping
        sorted_hunks = sorted(hunks, key=lambda h: h.start_line)
        for i in range(len(sorted_hunks) - 1):
            if sorted_hunks[i].end_line >= sorted_hunks[i + 1].start_line:
                raise ProposalGenerationError(
                    f"Conflicting overlapping repair hunks detected in file '{rel_path}'."
                )

        # Apply hunks from bottom to top to preserve line numbering
        modified_lines = list(orig_lines)
        for h in reversed(sorted_hunks):
            h_start = h.start_line - 1
            h_end = h.end_line
            rep_lines = h.replacement_content.splitlines(keepends=True)
            modified_lines[h_start:h_end] = rep_lines

        modified_text = "".join(modified_lines)
        mod_sha = hashlib.sha256(modified_text.encode("utf-8")).hexdigest()

        # Validate syntax of proposed file content
        syntax_res = validate_file_syntax(abs_path, modified_text, canonical_root)
        if not syntax_res.valid:
            raise ProposalGenerationError(
                f"Proposed patch creates syntax error in '{rel_path}': {syntax_res.error_message}"
            )

        diff = _generate_unified_diff(orig_text, modified_text, rel_path)
        affected_files.append(
            ProposalFile(
                rel_path=rel_path,
                original_file_sha256=orig_sha,
                replacement_file_sha256=mod_sha,
                hunks=sorted_hunks,
                diff=diff,
                language=syntax_res.language,
            )
        )

    # 5. Assemble verification plan
    target_ids = [f.id for f in target_findings]
    v_plan = ProposalVerificationPlan(
        target_finding_ids=target_ids,
        expected_resolved_findings=target_ids,
        prohibited_new_findings=[],
        syntax_validation_targets=[f.rel_path for f in affected_files],
        strategy="Post-repair scanner verification: assert all target findings resolved with zero new findings.",
    )

    now_dt = datetime.now(timezone.utc)
    proposal_id = ServerProposalStore.generate_proposal_id()
    created_at = now_dt.isoformat()
    expires_at = (now_dt + timedelta(hours=1)).isoformat()

    summary = (
        f"Coordinated repair for root cause '{matched_rc['candidate_id']}': "
        f"{matched_rc.get('description', '')}"
        if matched_rc
        else f"Deterministic repair for finding {target_findings[0].id} ({target_findings[0].rule_id})"
    )

    proposal = IntelligentRepairProposal(
        proposal_id=proposal_id,
        canonical_project_root=str(canonical_root),
        created_at=created_at,
        expires_at=expires_at,
        root_cause_id=matched_rc["candidate_id"] if matched_rc else None,
        target_finding_ids=target_ids,
        affected_files=affected_files,
        summary=summary,
        detailed_explanation=f"Applies deterministic evidence-driven alignment across {len(affected_files)} file(s) and {len(target_ids)} finding(s).",
        expected_result="Resolves all target API contract discrepancies cleanly.",
        risks_and_limitations=["Requires developer review before transaction execution."],
        verification_plan=v_plan,
        proposal_origin=ProposalOrigin.DETERMINISTIC,
        can_autofix=True,
        approval_state=ProposalApprovalState.PENDING_REVIEW,
    )

    # Persist server-side
    ServerProposalStore.save_proposal(canonical_root, proposal, allowed_roots=allowed_roots)
    return proposal
