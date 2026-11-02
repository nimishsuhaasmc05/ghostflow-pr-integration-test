from __future__ import annotations
import difflib
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .models import (
    Evidence,
    Finding,
    IdentityChange,
    PatchProposal,
    RepairApplyResult,
    RepairExplanation,
    RollbackResult,
    VerificationReport,
)
from .compatibility import map_py_to_ts, are_types_compatible

BACKUP_ID_RE = re.compile(r"^bk_\d{8}_\d{6}_[a-f0-9]{8}$")
SAFE_AUTOFIX_RULES: frozenset[str] = frozenset({"API002", "API003", "API004"})


def validate_safe_path(
    target_path: str | Path,
    base_root: Path,
    allowed_roots: list[Path] | None = None,
) -> Path:
    """Validate that target_path is strictly within base_root and allowed_roots.
    
    Prevents path traversal ('..'), absolute path escapes, and symlink escapes.
    """
    raw_str = str(target_path)
    if "\0" in raw_str:
        raise ValueError("Invalid path: null byte detected.")

    base_resolved = base_root.expanduser().resolve()

    # Verify base_root is within allowed_roots if provided
    if allowed_roots:
        resolved_allowed = [r.expanduser().resolve() for r in allowed_roots]
        if not any(base_resolved == r or r in base_resolved.parents for r in resolved_allowed):
            raise ValueError(f"Project root {base_resolved} is outside allowed roots.")

    # Check for explicit relative path traversal components before resolution
    p = Path(target_path)
    if ".." in p.parts:
        raise ValueError(f"Path traversal rejected: '..' is not allowed in '{target_path}'.")

    # Combine with base_resolved if relative
    candidate = p if p.is_absolute() else (base_resolved / p)
    candidate_resolved = candidate.resolve()

    # Reject if resolved path escapes base_resolved
    if candidate_resolved != base_resolved and base_resolved not in candidate_resolved.parents:
        raise ValueError(
            f"Path escape rejected: '{target_path}' resolves to '{candidate_resolved}', which is outside '{base_resolved}'."
        )

    # Also verify resolved path is within allowed_roots if provided
    if allowed_roots:
        resolved_allowed = [r.expanduser().resolve() for r in allowed_roots]
        if not any(candidate_resolved == r or r in candidate_resolved.parents for r in resolved_allowed):
            raise ValueError(
                f"Path escape rejected: '{candidate_resolved}' is outside allowed roots."
            )

    return candidate_resolved


class BackupManager:
    """Manages file backups for safe patching and rollback."""

    @staticmethod
    def _get_backup_dir(base_root: Path) -> Path:
        d = base_root / ".ghostflow" / "backups"
        d.mkdir(parents=True, exist_ok=True)
        return d

    @classmethod
    def create_backup(cls, base_root: Path, target_file: Path, rel_file: str) -> str:
        base_root = base_root.expanduser().resolve()
        backup_id = f"bk_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        backup_dir = cls._get_backup_dir(base_root) / backup_id
        backup_dir.mkdir(parents=True, exist_ok=True)

        content = target_file.read_bytes()
        sha = hashlib.sha256(content).hexdigest()

        backup_file = backup_dir / "original_content.bin"
        backup_file.write_bytes(content)

        meta = {
            "backup_id": backup_id,
            "rel_file": rel_file,
            "abs_file": str(target_file.resolve()),
            "content_hash": sha,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        (backup_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return backup_id

    @classmethod
    def restore_backup(
        cls,
        base_root: Path,
        backup_id: str,
        allowed_roots: list[Path] | None = None,
    ) -> tuple[Path, str, str]:
        """Restore file from backup and return (target_file_path, restored_content, rel_file)."""
        if not BACKUP_ID_RE.match(backup_id):
            raise ValueError(f"Invalid backup ID format: '{backup_id}'.")

        base_root = base_root.expanduser().resolve()
        backup_dir = cls._get_backup_dir(base_root) / backup_id
        meta_file = backup_dir / "meta.json"
        content_file = backup_dir / "original_content.bin"

        if not meta_file.exists() or not content_file.exists():
            raise ValueError(f"Backup '{backup_id}' not found or corrupted.")

        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        rel_file = meta["rel_file"]
        target_file = validate_safe_path(rel_file, base_root, allowed_roots)

        original_bytes = content_file.read_bytes()
        target_file.write_bytes(original_bytes)
        restored_text = original_bytes.decode("utf-8", errors="replace")
        return target_file, restored_text, rel_file


def explain_finding(finding: Finding, root_path: Path | None = None) -> RepairExplanation:
    """Generate structured, evidence-backed explanation for any finding API001–API010."""
    fe_ev = next((e for e in finding.evidence if e.role == "frontend"), None)
    be_ev = next((e for e in finding.evidence if e.role == "backend"), None)

    rule = finding.rule_id
    details = finding.details or {}

    if rule == "API001":
        fe_method = details.get("frontend_method", "HTTP")
        path = details.get("path", "")
        summary = f"No backend route found matching frontend call {fe_method} {path}."
        expected = f"A backend route declared for {fe_method} {path}."
        actual = f"Frontend sends {fe_method} {path}, but no matching endpoint is registered in backend routers."
        correction = f"Implement route handler for {fe_method} {path} in backend, or update frontend URL/prefix if misdirected."
        why = "Aligning routes ensures client calls reach a valid server handler instead of returning 404 Not Found."
        can_autofix = False

    elif rule == "API002":
        fe_method = details.get("frontend_method", "HTTP")
        path = details.get("path", "")
        summary = f"HTTP method mismatch on {path}: frontend calls {fe_method}, but backend expects different method(s)."
        expected = f"Frontend request using one of the declared backend methods for {path}."
        actual = f"Frontend sends {fe_method} request."
        correction = "Update frontend HTTP method to match declared backend route handler."
        why = "Prevents 405 Method Not Allowed responses at runtime."
        can_autofix = True

    elif rule == "API003":
        fe_params = details.get("frontend_params", [])
        be_params = details.get("backend_params", [])
        summary = f"Path parameter name mismatch: frontend uses {fe_params}, while backend route expects {be_params}."
        expected = f"Path parameter names in frontend URL template matching backend parameters {be_params}."
        actual = f"Frontend specifies parameter names {fe_params}."
        correction = f"Rename frontend path parameter(s) from {fe_params} to {be_params} in template string and function signature."
        why = "Ensures path parameters bind correctly to backend handler arguments without routing or extraction failure."
        can_autofix = True

    elif rule == "API004":
        param = details.get("parameter", "parameter")
        fe_type = details.get("frontend_type", "unknown")
        be_type = details.get("backend_type", "unknown")
        ts_type = map_py_to_ts(be_type)
        summary = f"Path parameter '{param}' type mismatch: frontend passes '{fe_type}', backend expects '{be_type}'."
        expected = f"Parameter '{param}' typed as '{ts_type}' to conform to backend '{be_type}'."
        actual = f"Frontend parameter typed as '{fe_type}'."
        correction = f"Change frontend parameter type for '{param}' to '{ts_type}'."
        why = "Prevents FastAPI 422 Unprocessable Entity path validation failures."
        can_autofix = True

    elif rule == "API005":
        field = details.get("field", "field")
        expected_type = details.get("expected_type", "unknown")
        model = details.get("model", "RequestModel")
        ts_type = map_py_to_ts(expected_type)
        summary = f"Frontend request payload is missing required field '{field}' ({expected_type}) expected by backend model '{model}'."
        expected = f"Frontend request payload type containing '{field}: {ts_type}'."
        actual = f"Frontend request interface omits '{field}'."
        correction = f"Add '{field}: {ts_type};' to the frontend request interface definition."
        why = f"Fulfills backend Pydantic validation requirements for '{model}', preventing runtime 422 validation errors."
        can_autofix = False

    elif rule == "API006":
        field = details.get("field", "field")
        fe_type = details.get("frontend_type", "unknown")
        be_type = details.get("backend_type", "unknown")
        ts_type = map_py_to_ts(be_type)
        summary = f"Request payload field '{field}' type mismatch: frontend sends '{fe_type}', backend expects '{be_type}'."
        expected = f"Frontend sends value compatible with backend type '{be_type}' ('{ts_type}')."
        actual = f"Frontend sends '{fe_type}'."
        correction = f"Update '{field}' in frontend request interface to '{ts_type}'."
        why = "Ensures JSON request payload deserializes cleanly into backend Pydantic model fields."
        can_autofix = False

    elif rule == "API007":
        field = details.get("field", "field")
        fe_type = details.get("frontend_type", "unknown")
        model = details.get("backend_model", "ResponseModel")
        summary = f"Frontend expects response field '{field}' ({fe_type}), but backend model '{model}' does not declare it."
        expected = f"Backend response model '{model}' providing field '{field}' or frontend handling its absence."
        actual = f"Field '{field}' is absent from backend response model."
        correction = f"Add '{field}' to backend model '{model}', or mark field optional in frontend response type."
        why = "Prevents frontend runtime errors when accessing properties that backend does not return."
        can_autofix = False

    elif rule == "API008":
        field = details.get("field", "field")
        fe_type = details.get("frontend_type", "unknown")
        be_type = details.get("backend_type", "unknown")
        ts_type = map_py_to_ts(be_type)
        summary = f"Response payload field '{field}' type mismatch: frontend expects '{fe_type}', backend returns '{be_type}'."
        expected = f"Frontend response type aligned with backend returned type '{be_type}' ('{ts_type}')."
        actual = f"Frontend expects '{fe_type}', backend returns '{be_type}'."
        correction = f"Update frontend response interface field '{field}' to '{ts_type}'."
        why = "Guarantees frontend TypeScript types accurately reflect the payload received over the wire."
        can_autofix = False

    elif rule == "API009":
        field = details.get("field", "field")
        summary = f"Nullability or optionality mismatch for field '{field}' across frontend and backend."
        expected = "Consistent optionality or nullability handling between client and server."
        actual = f"Field '{field}' optionality differs between frontend interface and backend schema."
        correction = f"Align optionality modifier ('?') or nullable union ('| null') for '{field}' in frontend interface."
        why = "Prevents null pointer exceptions in frontend and 422 errors on backend."
        can_autofix = False

    elif rule == "API010":
        method = details.get("method", "HTTP")
        norm_path = details.get("normalized_path", "")
        count = details.get("count", 2)
        summary = f"Backend declares {count} duplicate route handlers for {method} {norm_path}."
        expected = "A single unambiguous route handler for each HTTP method and path."
        actual = f"{count} duplicate route handlers registered in backend."
        correction = "Consolidate or delete redundant route handler declarations in backend."
        why = "Eliminates route shadowing and non-deterministic routing behavior."
        can_autofix = False

    elif rule == "INT001":
        prefix = details.get("prefix", "")
        direction = details.get("direction", "")
        fe_path = details.get("frontend_path", "")
        be_path = details.get("backend_path", "")
        summary = f"API base path prefix drift: frontend path '{fe_path}' differs from backend route '{be_path}' by prefix '{prefix}'."
        expected = "Consistent base prefix across frontend API clients and backend route registrations."
        actual = f"Prefix '{prefix}' is {'present in frontend but missing in backend' if direction == 'frontend_has_prefix' else 'present in backend but missing in frontend'}."
        correction = "Align frontend client baseURL or backend router mount prefix."
        why = "Resolves 404 routing errors caused by mismatched base path prefixes."
        can_autofix = False

    else:
        summary = finding.message
        expected = "Contract match across frontend and backend layers."
        actual = finding.message
        correction = finding.recommendation
        why = "Resolves API contract discrepancy."
        can_autofix = False

    return RepairExplanation(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        title=finding.title,
        mismatch_summary=summary,
        frontend_evidence=fe_ev,
        backend_evidence=be_ev,
        expected_behavior=expected,
        actual_behavior=actual,
        suggested_correction=correction,
        why_correction_works=why,
        confidence=finding.confidence,
        can_autofix=can_autofix,
    )


def _generate_diff(file_lines: list[str], new_lines: list[str], rel_file: str) -> str:
    """Generate git-compatible unified diff."""
    norm_path = rel_file.replace("\\", "/")
    diff = list(
        difflib.unified_diff(
            file_lines,
            new_lines,
            fromfile=f"a/{norm_path}",
            tofile=f"b/{norm_path}",
            lineterm="",
        )
    )
    return "\n".join(diff)


def propose_patch(
    finding: Finding,
    root_path: Path,
    allowed_roots: list[Path] | None = None,
) -> PatchProposal:
    """Generate a minimal, deterministic code patch proposal for supported findings."""
    root = root_path.expanduser().resolve()
    explanation = explain_finding(finding, root)

    # 1. Reject ambiguous, unsupported, or disabled rules
    if finding.rule_id not in SAFE_AUTOFIX_RULES or not explanation.can_autofix:
        return PatchProposal(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file="",
            start_line=0,
            end_line=0,
            original_code="",
            replacement_code="",
            explanation=f"Automatic repair for {finding.rule_id} is ambiguous: {explanation.suggested_correction}",
            confidence=finding.confidence,
            can_autofix=False,
            validation_status="ambiguous",
            content_hash="",
            diff="",
        )

    fe_ev = next((e for e in finding.evidence if e.role == "frontend"), None)
    if not fe_ev or not fe_ev.file:
        return PatchProposal(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file="",
            start_line=0,
            end_line=0,
            original_code="",
            replacement_code="",
            explanation="Missing frontend source evidence to locate patch target.",
            confidence=finding.confidence,
            can_autofix=False,
            validation_status="unsupported",
            content_hash="",
            diff="",
        )

    # 2. Safely resolve target file
    try:
        target_abs = validate_safe_path(fe_ev.file, root, allowed_roots)
    except Exception as exc:
        return PatchProposal(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file=fe_ev.file,
            start_line=0,
            end_line=0,
            original_code="",
            replacement_code="",
            explanation=f"Path safety error: {exc}",
            confidence=finding.confidence,
            can_autofix=False,
            validation_status="unsupported",
            content_hash="",
            diff="",
        )

    if not target_abs.is_file():
        return PatchProposal(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file=fe_ev.file,
            start_line=0,
            end_line=0,
            original_code="",
            replacement_code="",
            explanation=f"Target file does not exist: {fe_ev.file}",
            confidence=finding.confidence,
            can_autofix=False,
            validation_status="stale",
            content_hash="",
            diff="",
        )

    file_text = target_abs.read_text(encoding="utf-8")
    file_lines = file_text.splitlines(keepends=True)
    content_hash = hashlib.sha256(file_text.encode("utf-8")).hexdigest()
    details = finding.details or {}

    original_code = ""
    replacement_code = ""
    start_line = 0
    end_line = 0

    # Rule API003: Path parameter name mismatch
    if finding.rule_id == "API003":
        fe_params = details.get("frontend_params", [])
        be_params = details.get("backend_params", [])
        if fe_params and be_params:
            fe_name = fe_params[0]
            be_name = be_params[0]
            # Search around evidence line for enclosing function and fetch call
            target_line_idx = max(0, fe_ev.line - 1)
            # Find function header starting within 5 lines before or at target_line_idx
            func_start_idx = target_line_idx
            for idx in range(target_line_idx, max(-1, target_line_idx - 6), -1):
                if re.search(rf"\b(function\s+\w+|\w+\s*=\s*(?:async\s*)?\([^)]*\))\s*", file_lines[idx]):
                    func_start_idx = idx
                    break

            # Find end of function block or fetch call (up to 5 lines after target_line_idx)
            func_end_idx = target_line_idx
            for idx in range(target_line_idx, min(len(file_lines), target_line_idx + 6)):
                if "}" in file_lines[idx] or ");" in file_lines[idx]:
                    func_end_idx = idx
                    break

            excerpt_lines = file_lines[func_start_idx : func_end_idx + 1]
            original_code = "".join(excerpt_lines)

            # Replace param in template `${fe_name}` -> `${be_name}` and signature `(fe_name:` -> `(be_name:`
            repl = original_code
            repl = re.sub(rf"\$\{{\s*{re.escape(fe_name)}\s*\}}", f"${{{be_name}}}", repl)
            repl = re.sub(rf"\b{re.escape(fe_name)}(?=\s*[:,\)])", be_name, repl)

            if repl != original_code:
                replacement_code = repl
                start_line = func_start_idx + 1
                end_line = func_end_idx + 1

    # Rule API004: Path parameter type mismatch
    elif finding.rule_id == "API004":
        param = details.get("parameter", "")
        be_type = details.get("backend_type", "")
        ts_type = map_py_to_ts(be_type)
        if param and ts_type:
            target_line_idx = max(0, fe_ev.line - 1)
            # Scan backward up to 5 lines to find parameter typing in function signature
            found_idx = None
            for idx in range(target_line_idx, max(-1, target_line_idx - 6), -1):
                if re.search(rf"\b{re.escape(param)}\s*:\s*[A-Za-z0-9_]+", file_lines[idx]):
                    found_idx = idx
                    break
            if found_idx is not None:
                original_line = file_lines[found_idx]
                repl_line = re.sub(
                    rf"(\b{re.escape(param)}\s*:\s*)[A-Za-z0-9_]+",
                    rf"\g<1>{ts_type}",
                    original_line,
                )
                if repl_line != original_line:
                    original_code = original_line
                    replacement_code = repl_line
                    start_line = found_idx + 1
                    end_line = found_idx + 1

    # Rule API005: Request payload missing required field
    elif finding.rule_id == "API005":
        field = details.get("field", "")
        expected_type = details.get("expected_type", "")
        ts_type = map_py_to_ts(expected_type)

        # Find frontend interface matching the request
        # First check if finding details mention model name or search for interface in frontend files
        model_name = details.get("model", "")
        # Look for interface CreateOrderRequest or similar in target file
        # Search file for interface or type definition
        pattern = re.compile(r"(export\s+)?(interface|type)\s+([A-Za-z0-9_$]+)\s*(?:=\s*)?\{")
        interface_ranges: list[tuple[str, int, int]] = []
        for match in pattern.finditer(file_text):
            name = match.group(3)
            open_idx = file_text.find("{", match.start())
            # Find matching close brace
            depth = 0
            close_idx = -1
            for ci in range(open_idx, len(file_text)):
                if file_text[ci] == "{":
                    depth += 1
                elif file_text[ci] == "}":
                    depth -= 1
                    if depth == 0:
                        close_idx = ci
                        break
            if close_idx != -1:
                start_l = file_text.count("\n", 0, match.start()) + 1
                end_l = file_text.count("\n", 0, close_idx) + 1
                interface_ranges.append((name, start_l, end_l))

        # Check which interface is relevant (e.g., used by request or matches request name)
        chosen_range = None
        for name, sl, el in interface_ranges:
            if "request" in name.lower() or "order" in name.lower() or name.lower() in model_name.lower() or model_name.lower() in name.lower():
                chosen_range = (name, sl, el)
                break
        if not chosen_range and interface_ranges:
            chosen_range = interface_ranges[0]

        if chosen_range and field and ts_type:
            name, sl, el = chosen_range
            excerpt_lines = file_lines[sl - 1 : el]
            original_code = "".join(excerpt_lines)

            # Insert missing field before the closing brace '}'
            # Check indentation of existing fields
            indent = "  "
            for line in excerpt_lines[1:-1]:
                m = re.match(r"^(\s+)\w+", line)
                if m:
                    indent = m.group(1)
                    break

            new_field_line = f"{indent}{field}: {ts_type};\n"
            # Insert before last line
            repl_lines = list(excerpt_lines)
            repl_lines.insert(-1, new_field_line)
            replacement_code = "".join(repl_lines)
            start_line = sl
            end_line = el

    # Rule API006: Request payload field type mismatch
    elif finding.rule_id == "API006":
        field = details.get("field", "")
        be_type = details.get("backend_type", "")
        ts_type = map_py_to_ts(be_type)
        if field and ts_type:
            target_line_idx = max(0, fe_ev.line - 1)
            # Search around target line for field definition
            found_idx = None
            for idx in range(max(0, target_line_idx - 5), min(len(file_lines), target_line_idx + 6)):
                if re.search(rf"\b{re.escape(field)}\s*:\s*[A-Za-z0-9_]+", file_lines[idx]):
                    found_idx = idx
                    break
            if found_idx is not None:
                original_line = file_lines[found_idx]
                repl_line = re.sub(
                    rf"(\b{re.escape(field)}\s*:\s*)[^;,\n]+",
                    rf"\g<1>{ts_type}",
                    original_line,
                )
                if repl_line != original_line:
                    original_code = original_line
                    replacement_code = repl_line
                    start_line = found_idx + 1
                    end_line = found_idx + 1

    # Rule API002: HTTP method mismatch
    elif finding.rule_id == "API002":
        be_ev = next((e for e in finding.evidence if e.role == "backend"), None)
        # Check backend method
        if be_ev and be_ev.source:
            m = re.search(r"@(?:app|router|[A-Za-z0-9_]+)\.(get|post|put|patch|delete)", be_ev.source, re.IGNORECASE)
            if m:
                target_method = m.group(1).upper()
                target_line_idx = max(0, fe_ev.line - 1)
                found_idx = None
                for idx in range(target_line_idx, min(len(file_lines), target_line_idx + 8)):
                    if re.search(r"\bmethod\s*:\s*['\"][A-Z]+['\"]", file_lines[idx]) or re.search(r"\baxios\.[a-z]+", file_lines[idx]):
                        found_idx = idx
                        break
                if found_idx is not None:
                    original_line = file_lines[found_idx]
                    # Replace method: 'POST' or axios.post
                    repl_line = re.sub(r"\bmethod\s*:\s*['\"][A-Z]+['\"]", f"method: '{target_method}'", original_line)
                    repl_line = re.sub(r"\baxios\.[a-z]+", f"axios.{target_method.lower()}", repl_line)
                    if repl_line != original_line:
                        original_code = original_line
                        replacement_code = repl_line
                        start_line = found_idx + 1
                        end_line = found_idx + 1

    # Rule API008: Response field type mismatch
    elif finding.rule_id == "API008":
        field = details.get("field", "")
        be_type = details.get("backend_type", "")
        ts_type = map_py_to_ts(be_type)
        if field and ts_type:
            target_line_idx = max(0, fe_ev.line - 1)
            found_idx = None
            for idx in range(max(0, target_line_idx - 5), min(len(file_lines), target_line_idx + 6)):
                if re.search(rf"\b{re.escape(field)}\s*:\s*[A-Za-z0-9_]+", file_lines[idx]):
                    found_idx = idx
                    break
            if found_idx is not None:
                original_line = file_lines[found_idx]
                repl_line = re.sub(
                    rf"(\b{re.escape(field)}\s*:\s*)[^;,\n]+",
                    rf"\g<1>{ts_type}",
                    original_line,
                )
                if repl_line != original_line:
                    original_code = original_line
                    replacement_code = repl_line
                    start_line = found_idx + 1
                    end_line = found_idx + 1

    # Rule API009: Optionality mismatch
    elif finding.rule_id == "API009":
        field = details.get("field", "")
        target_line_idx = max(0, fe_ev.line - 1)
        found_idx = None
        for idx in range(max(0, target_line_idx - 5), min(len(file_lines), target_line_idx + 6)):
            if re.search(rf"\b{re.escape(field)}\??\s*:", file_lines[idx]):
                found_idx = idx
                break
        if found_idx is not None:
            original_line = file_lines[found_idx]
            if details.get("backend_required") and not details.get("frontend_required", True):
                # Remove '?' to make required
                repl_line = re.sub(rf"(\b{re.escape(field)})\?\s*:", r"\1:", original_line)
            else:
                # Add '?' to make optional
                repl_line = re.sub(rf"(\b{re.escape(field)})\s*:", r"\1?:", original_line)
            if repl_line != original_line:
                original_code = original_line
                replacement_code = repl_line
                start_line = found_idx + 1
                end_line = found_idx + 1

    # Check if patch was successfully generated and line range is valid
    if (
        not original_code
        or not replacement_code
        or start_line < 1
        or end_line < start_line
        or end_line > len(file_lines)
        or "".join(file_lines[start_line - 1 : end_line]) != original_code
    ):
        return PatchProposal(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file=fe_ev.file,
            start_line=0,
            end_line=0,
            original_code="",
            replacement_code="",
            explanation=f"Could not generate deterministic patch for {finding.rule_id}: {explanation.suggested_correction}",
            confidence=finding.confidence,
            can_autofix=False,
            validation_status="ambiguous",
            content_hash=content_hash,
            diff="",
        )

    # Compute diff using the exact line range to avoid collision with identical code blocks
    new_file_lines = (
        file_lines[: start_line - 1]
        + (replacement_code.splitlines(keepends=True) if replacement_code else [])
        + file_lines[end_line:]
    )
    diff_text = _generate_diff(file_lines, new_file_lines, fe_ev.file)

    return PatchProposal(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        file=fe_ev.file,
        start_line=start_line,
        end_line=end_line,
        original_code=original_code,
        replacement_code=replacement_code,
        explanation=explanation.suggested_correction,
        confidence=finding.confidence,
        can_autofix=True,
        validation_status="valid",
        content_hash=content_hash,
        diff=diff_text,
    )


def compare_scan_findings(
    previous_findings: list[Finding | dict],
    new_findings: list[Finding | dict],
) -> VerificationReport:
    """Compare previous and new scan findings with semantic identity preservation and identity change tracking."""
    def to_finding(item: Any) -> Finding:
        if isinstance(item, dict):
            return Finding(**item)
        return item

    prev_list = [to_finding(f) for f in previous_findings]
    new_list = [to_finding(f) for f in new_findings]

    def _normalize_path(p: str) -> str:
        return re.sub(r"\{[^{}]+\}", "{}", p).rstrip("/") or "/"

    def _get_element_slot(f: Finding) -> str:
        d = f.details or {}
        if f.rule_id == "API004":
            return str(d.get("backend_param") or d.get("param_index") or d.get("parameter") or "")
        if f.rule_id == "API003":
            return "path_params"
        if f.rule_id in {"API005", "API006", "API007", "API008", "API009"}:
            return str(d.get("field") or "")
        if f.rule_id == "API010":
            return str(d.get("count") or "")
        return ""

    def _get_target_endpoint(f: Finding) -> tuple[str, str]:
        d = f.details or {}
        method = str(d.get("method") or d.get("frontend_method") or "")
        path = str(d.get("normalized_path") or d.get("path") or "")
        if not path:
            # Fall back to evidence source or message
            for ev in f.evidence:
                m = re.search(r"['\"](/api/[^'\"]+)['\"]", ev.source or "")
                if m:
                    path = m.group(1)
                    break
        norm_path = _normalize_path(path) if path else ""
        return (method.upper(), norm_path)

    def _get_semantic_key(f: Finding) -> tuple[str, str, str, str]:
        method, norm_path = _get_target_endpoint(f)
        slot = _get_element_slot(f)
        return (f.rule_id, method, norm_path, slot)

    exact_matched_prev: set[str] = set()
    exact_matched_new: set[str] = set()
    unchanged_ids: list[str] = []

    # Stage 1: Exact ID match
    new_by_id = {f.id: f for f in new_list}
    for p in prev_list:
        if p.id in new_by_id:
            exact_matched_prev.add(p.id)
            exact_matched_new.add(p.id)
            unchanged_ids.append(p.id)

    unmatched_prev = [p for p in prev_list if p.id not in exact_matched_prev]
    unmatched_new = [n for n in new_list if n.id not in exact_matched_new]

    # Stage 2: Semantic defect matching (same rule, endpoint, parameter/field slot)
    identity_changes: list[IdentityChange] = []
    semantic_matched_prev: set[str] = set()
    semantic_matched_new: set[str] = set()

    for p in unmatched_prev:
        p_key = _get_semantic_key(p)
        # Find matching candidate in unmatched_new
        match_candidate = None
        for n in unmatched_new:
            if n.id in semantic_matched_new:
                continue
            n_key = _get_semantic_key(n)
            if p_key == n_key and p.rule_id == n.rule_id:
                match_candidate = n
                break

        if match_candidate:
            semantic_matched_prev.add(p.id)
            semantic_matched_new.add(match_candidate.id)

            reason_desc = (
                f"Defect {p.rule_id} persists across source modification: "
                f"finding ID shifted from {p.id} to {match_candidate.id} "
                f"due to parameter renaming or file layout changes."
            )
            identity_changes.append(IdentityChange(
                old_id=p.id,
                new_id=match_candidate.id,
                rule_id=p.rule_id,
                reason=reason_desc,
                details={
                    "old_details": p.details,
                    "new_details": match_candidate.details,
                    "endpoint": f"{p_key[1]} {p_key[2]}",
                    "slot": p_key[3],
                },
            ))

    # All still-existing finding IDs in new scan
    still_existing_ids = sorted(list(set(unchanged_ids) | {ic.new_id for ic in identity_changes}))

    # Stage 3: Truly resolved finding IDs (in previous, but not matched exactly or semantically)
    resolved_ids = sorted([
        p.id for p in prev_list
        if p.id not in exact_matched_prev and p.id not in semantic_matched_prev
    ])

    # Stage 4: Truly introduced finding IDs (in new, but not matched exactly or semantically)
    introduced_ids = sorted([
        n.id for n in new_list
        if n.id not in exact_matched_new and n.id not in semantic_matched_new
    ])

    return VerificationReport(
        resolved_finding_ids=resolved_ids,
        unchanged_finding_ids=sorted(unchanged_ids),
        still_existing_finding_ids=still_existing_ids,
        introduced_finding_ids=introduced_ids,
        identity_changes=identity_changes,
        previous_findings_count=len(previous_findings),
        new_findings_count=len(new_findings),
        new_findings=new_list,
    )


def apply_patch(
    proposal: PatchProposal,
    root_path: Path,
    previous_findings: list[Finding | dict] | None = None,
    allowed_roots: list[Path] | None = None,
) -> RepairApplyResult:
    """Validate and apply an approved patch proposal, creating a backup and re-scanning to verify."""
    from .analyzer import scan_project

    root = root_path.expanduser().resolve()

    if not proposal.can_autofix or proposal.validation_status != "valid":
        return RepairApplyResult(
            status="failed",
            message=f"Cannot apply proposal with validation status '{proposal.validation_status}'.",
            file=proposal.file,
        )

    if proposal.rule_id not in SAFE_AUTOFIX_RULES:
        return RepairApplyResult(
            status="failed",
            message=f"Rule '{proposal.rule_id}' is not supported for automatic patch application.",
            file=proposal.file,
        )

    # 1. Path safety verification
    try:
        target_abs = validate_safe_path(proposal.file, root, allowed_roots)
    except Exception as exc:
        return RepairApplyResult(
            status="failed",
            message=f"Path validation failed: {exc}",
            file=proposal.file,
        )

    if not target_abs.is_file():
        return RepairApplyResult(
            status="stale",
            message=f"Target file no longer exists: {proposal.file}",
            file=proposal.file,
        )

    # 2. Check current content and hash for staleness
    current_text = target_abs.read_text(encoding="utf-8")
    current_hash = hashlib.sha256(current_text.encode("utf-8")).hexdigest()

    if not proposal.content_hash or current_hash != proposal.content_hash:
        return RepairApplyResult(
            status="stale",
            message="Target file has changed since the patch proposal was generated. Re-scan required.",
            file=proposal.file,
        )

    current_lines = current_text.splitlines(keepends=True)

    # 3. Validate line ranges
    if (
        proposal.start_line < 1
        or proposal.end_line < proposal.start_line
        or proposal.end_line > len(current_lines)
    ):
        return RepairApplyResult(
            status="failed",
            message=f"Target line range {proposal.start_line}-{proposal.end_line} is out of bounds (file has {len(current_lines)} lines).",
            file=proposal.file,
        )

    # 4. Verify that target code excerpt at the exact line range matches proposal
    target_excerpt = "".join(current_lines[proposal.start_line - 1 : proposal.end_line])
    if target_excerpt != proposal.original_code:
        return RepairApplyResult(
            status="stale",
            message="Target code excerpt at specified line range no longer matches file content.",
            file=proposal.file,
        )

    # 5. Create backup before modifying file
    backup_id = BackupManager.create_backup(root, target_abs, proposal.file)

    # 6. Apply replacement strictly to the validated line range
    try:
        new_text = (
            "".join(current_lines[: proposal.start_line - 1])
            + proposal.replacement_code
            + "".join(current_lines[proposal.end_line :])
        )
        target_abs.write_text(new_text, encoding="utf-8")
    except Exception as exc:
        return RepairApplyResult(
            status="failed",
            message=f"Failed to apply patch to file: {exc}",
            file=proposal.file,
            backup_id=backup_id,
        )

    # 7. Re-run static scan for verification
    new_scan = scan_project(str(root))
    new_findings = new_scan.get("findings", [])

    verification = compare_scan_findings(previous_findings or [], new_findings)

    return RepairApplyResult(
        status="applied",
        message="Patch applied and verified with fresh local static scan.",
        backup_id=backup_id,
        file=proposal.file,
        verification=verification,
    )


def rollback_patch(
    backup_id: str,
    root_path: Path,
    previous_findings: list[Finding | dict] | None = None,
    allowed_roots: list[Path] | None = None,
) -> RollbackResult:
    """Restore file from backup and run static scan to verify state."""
    from .analyzer import scan_project

    root = root_path.expanduser().resolve()

    try:
        target_abs, _, rel_file = BackupManager.restore_backup(root, backup_id, allowed_roots)
    except Exception as exc:
        return RollbackResult(
            status="failed",
            message=f"Rollback failed: {exc}",
            file="",
        )

    new_scan = scan_project(str(root))
    new_findings = new_scan.get("findings", [])

    verification = compare_scan_findings(previous_findings or [], new_findings)

    return RollbackResult(
        status="rolled_back",
        message="Successfully rolled back to backup state and verified with fresh static scan.",
        file=rel_file,
        verification=verification,
    )
