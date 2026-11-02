"""GhostFlow GitHub Pull Request Intelligence Engine.
===================================================
Orchestrates Pull Request scanning, base vs. head transition verification,
Git-aware change impact correlation, quality gate evaluation, and markdown
report synthesis for GitHub Actions workflows.

Guarantees:
- Pure static analysis: never executes arbitrary repository code or migrations.
- Never blocks PRs solely on candidate change impact predictions.
- Robust in full checkouts, shallow clones, and single-branch checkouts.
- Zero credential exposure in logs or reports.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Sequence
from pydantic import BaseModel, Field

from .analyzer import scan_project
from .change_impact import analyze_change_impact, ChangeImpactReport, ChangedFile
from .models import Finding
from .verification import verify_scan_transition, IndependentVerificationReport, CategorizedFinding


class QualityGateConfig(BaseModel):
    """Configuration for Pull Request quality gate evaluation."""
    mode: str = "report"  # "report", "warn", "enforce"
    fail_on: str = "high"  # "high", "medium", or comma-separated rule list (e.g. "API001,DB001,DB007")
    only_new: bool = True  # If true, gate only fails on newly introduced findings in this PR


class PRAnalysisResult(BaseModel):
    """Comprehensive structured outcome of Pull Request intelligence scan."""
    project_path: str
    base_ref: str | None = None
    head_ref: str | None = None
    base_sha: str | None = None
    head_sha: str | None = None
    base_scan_available: bool = False
    
    # Findings breakdown
    head_findings: list[dict[str, Any]] = Field(default_factory=list)
    base_findings: list[dict[str, Any]] = Field(default_factory=list)
    new_findings: list[dict[str, Any]] = Field(default_factory=list)
    existing_findings: list[dict[str, Any]] = Field(default_factory=list)
    resolved_findings: list[dict[str, Any]] = Field(default_factory=list)
    
    # Specific categories
    database_findings: list[dict[str, Any]] = Field(default_factory=list)
    root_causes: list[dict[str, Any]] = Field(default_factory=list)
    
    # Impact and Verification
    change_impact: ChangeImpactReport | None = None
    verification: IndependentVerificationReport | None = None
    
    # Quality Gate
    gate_mode: str = "report"
    gate_verdict: str = "PASS"  # "PASS", "WARN", "FAIL"
    gate_violations: list[dict[str, Any]] = Field(default_factory=list)
    gate_explanation: str = ""
    
    # Diagnostics & Unverified areas
    unverified_areas: list[str] = Field(default_factory=list)
    total_files_scanned: int = 0
    frontend_calls_count: int = 0
    backend_routes_count: int = 0


def _run_git(args: list[str], cwd: Path, timeout: float = 6.0) -> tuple[int, str, str]:
    """Execute git command safely with strict timeout."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


def _resolve_git_sha(ref: str, cwd: Path) -> str | None:
    code, out, _ = _run_git(["rev-parse", ref], cwd=cwd)
    return out if code == 0 and len(out) >= 7 else None


def _get_changed_files_between(base_ref: str, head_ref: str, cwd: Path) -> list[str]:
    """Get list of relative paths modified between base and head."""
    # Try triple-dot diff first (merge-base to head)
    code, out, _ = _run_git(["diff", "--name-only", f"{base_ref}...{head_ref}"], cwd=cwd)
    if code != 0 or not out:
        # Fall back to two-dot diff
        code, out, _ = _run_git(["diff", "--name-only", base_ref, head_ref], cwd=cwd)
    if code == 0 and out:
        return [line.strip().replace("\\", "/") for line in out.splitlines() if line.strip()]
    return []


def _extract_primary_file(finding: dict[str, Any]) -> str:
    ev_list = finding.get("evidence", [])
    if ev_list and isinstance(ev_list, list) and len(ev_list) > 0:
        ev = ev_list[0]
        if isinstance(ev, dict):
            return ev.get("file", "").replace("\\", "/").strip()
    return ""


def _scan_base_revision_safely(
    cwd: Path,
    base_ref: str,
    openapi_path: str | None = None,
    auto_detect_openapi: bool = True,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Attempt an isolated, ephemeral scan of the base revision without mutating workspace."""
    unverified_notes: list[str] = []
    
    # Check if base_ref resolves
    code, base_sha, _ = _run_git(["rev-parse", "--verify", base_ref], cwd=cwd)
    if code != 0 or not base_sha:
        unverified_notes.append(f"Base ref '{base_ref}' could not be resolved in local git history (shallow clone or remote branch not fetched).")
        return None, unverified_notes

    temp_dir = Path(tempfile.mkdtemp(prefix="ghostflow_base_"))
    try:
        # Attempt 1: git archive (safest, fast, does not need worktree support)
        archive_proc = subprocess.run(
            ["git", "archive", base_sha],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8.0,
        )
        if archive_proc.returncode == 0 and archive_proc.stdout:
            import tarfile
            import io
            import sys
            with tarfile.open(fileobj=io.BytesIO(archive_proc.stdout), mode="r:*") as tar:
                extract_kwargs = {"filter": "data"} if sys.version_info >= (3, 12) else {}
                tar.extractall(path=str(temp_dir), **extract_kwargs)
            
            # Scan the base snapshot
            base_report = scan_project(
                str(temp_dir),
                openapi_path=openapi_path,
                auto_detect_openapi=auto_detect_openapi,
            )
            return base_report, unverified_notes
    except Exception as exc:
        unverified_notes.append(f"Base snapshot extraction via git archive encountered: {exc}")

    try:
        # Attempt 2: git worktree add
        worktree_code, _, wt_err = _run_git(["worktree", "add", "--detach", str(temp_dir), base_sha], cwd=cwd)
        if worktree_code == 0:
            base_report = scan_project(
                str(temp_dir),
                openapi_path=openapi_path,
                auto_detect_openapi=auto_detect_openapi,
            )
            # Remove worktree immediately
            _run_git(["worktree", "remove", "--force", str(temp_dir)], cwd=cwd)
            return base_report, unverified_notes
        else:
            unverified_notes.append(f"Base git worktree creation skipped: {wt_err}")
    except Exception as exc:
        unverified_notes.append(f"Base git worktree scan encountered: {exc}")
    finally:
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)

    return None, unverified_notes


def evaluate_quality_gate(
    new_findings: list[dict[str, Any]],
    all_findings: list[dict[str, Any]],
    gate_config: QualityGateConfig,
) -> tuple[str, list[dict[str, Any]], str]:
    """Evaluate quality gate against configured mode and rules.

    Modes:
    - 'report' (or 'report-only'): never fails gate (verdict = PASS).
    - 'warn': never fails gate (verdict = WARN if violations present, else PASS).
    - 'enforce': fails gate (verdict = FAIL if violations present, else PASS).

    Guarantees:
    - Only confirmed static findings can fail the gate.
    - Candidate change impact predictions NEVER fail the gate.
    """
    mode = gate_config.mode.lower().strip()
    if mode in ("report-only", "report_only"):
        mode = "report"

    target_pool = new_findings if gate_config.only_new else all_findings
    violations: list[dict[str, Any]] = []

    fail_spec = gate_config.fail_on.strip()
    specific_rules = {r.strip().upper() for r in fail_spec.split(",") if r.strip() and not r.strip().lower() in ("high", "medium", "low")}
    severity_threshold = fail_spec.lower() if fail_spec.lower() in ("high", "medium", "low") else None

    for f in target_pool:
        rule_id = f.get("rule_id", "").upper()
        severity = f.get("severity", "medium").lower()

        is_violation = False
        if specific_rules and rule_id in specific_rules:
            is_violation = True
        elif severity_threshold == "high" and severity == "high":
            is_violation = True
        elif severity_threshold == "medium" and severity in ("high", "medium"):
            is_violation = True
        elif severity_threshold == "low":
            is_violation = True

        if is_violation:
            violations.append(f)

    if not violations:
        return "PASS", [], "Quality gate passed with 0 confirmed defect violations."

    if mode == "report":
        explanation = (
            f"Report mode active: {len(violations)} defect(s) detected matching criteria "
            f"('{gate_config.fail_on}'), but quality gate is non-blocking."
        )
        return "PASS", violations, explanation

    if mode == "warn":
        explanation = (
            f"Warning mode active: {len(violations)} defect(s) detected matching criteria "
            f"('{gate_config.fail_on}'). PR is not blocked, but resolution is strongly recommended."
        )
        return "WARN", violations, explanation

    # enforce mode
    explanation = (
        f"Enforcement mode active: {len(violations)} confirmed defect(s) detected matching criteria "
        f"('{gate_config.fail_on}'). Quality gate failed."
    )
    return "FAIL", violations, explanation


def analyze_pull_request(
    project_path: str | Path,
    base_ref: str | None = None,
    head_ref: str | None = "HEAD",
    openapi_path: str | None = None,
    auto_detect_openapi: bool = True,
    gate_config: QualityGateConfig | None = None,
) -> PRAnalysisResult:
    """Execute complete Pull Request intelligence analysis.

    1. Scans project head workspace.
    2. Gathers Git changed files and diff.
    3. Runs Git-aware change impact analysis.
    4. Safely attempts base snapshot scan if base_ref provided.
    5. Categorizes findings into new, existing, and resolved.
    6. Identifies database schema issues and root causes.
    7. Evaluates configurable quality gate.
    """
    if gate_config is None:
        gate_config = QualityGateConfig()

    root = Path(project_path).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Project directory '{project_path}' does not exist or is not a directory.")

    # 1. Scan current HEAD workspace
    head_report = scan_project(
        str(root),
        openapi_path=openapi_path,
        auto_detect_openapi=auto_detect_openapi,
    )

    head_findings = head_report.get("findings", [])
    disagreements = head_report.get("openapi_disagreements", [])
    # Combine findings with OAS disagreements if any
    all_head_findings = list(head_findings) + list(disagreements)

    total_files = len(head_report.get("files", []))
    frontend_calls = head_report.get("frontend_calls", 0)
    backend_routes = head_report.get("backend_routes", 0)

    # Database findings
    db_findings = [f for f in all_head_findings if f.get("category") == "Database Schema" or f.get("rule_id", "").startswith("DB")]
    root_causes = head_report.get("root_causes", [])

    # 2. Git inspection & Changed files
    head_sha = _resolve_git_sha(head_ref or "HEAD", cwd=root)
    base_sha = _resolve_git_sha(base_ref, cwd=root) if base_ref else None

    changed_files_list: list[str] = []
    if base_ref:
        changed_files_list = _get_changed_files_between(base_ref, head_ref or "HEAD", cwd=root)

    # 3. Change Impact Analysis
    change_impact = analyze_change_impact(
        root=root,
        base_ref=base_ref,
        calls=None,
        routes=None,
        models=None,
    )

    # 4. Base Snapshot Scan (if base_ref specified and reachable)
    base_report: dict[str, Any] | None = None
    unverified_areas: list[str] = []
    base_scan_available = False

    if base_ref:
        base_report, unverified = _scan_base_revision_safely(
            cwd=root,
            base_ref=base_ref,
            openapi_path=openapi_path,
            auto_detect_openapi=auto_detect_openapi,
        )
        unverified_areas.extend(unverified)
        if base_report is not None:
            base_scan_available = True

    # 5. Finding Categorization (New, Existing, Resolved)
    new_findings: list[dict[str, Any]] = []
    existing_findings: list[dict[str, Any]] = []
    resolved_findings: list[dict[str, Any]] = []
    verification_report: IndependentVerificationReport | None = None

    if base_scan_available and base_report is not None:
        base_findings = list(base_report.get("findings", [])) + list(base_report.get("openapi_disagreements", []))
        # Use Independent Verification Engine
        verification_report = verify_scan_transition(base_findings, all_head_findings)

        # Categorize according to verification engine
        resolved_ids = set(verification_report.resolved_finding_ids)
        still_existing_ids = set(verification_report.still_existing_finding_ids)
        introduced_ids = set(verification_report.introduced_finding_ids)

        for f in all_head_findings:
            fid = f.get("id")
            if fid in introduced_ids:
                new_findings.append(f)
            else:
                existing_findings.append(f)

        for f in base_findings:
            if f.get("id") in resolved_ids:
                resolved_findings.append(f)
    else:
        # Fallback heuristic when base git checkout is unavailable:
        # A finding is 'new' if its primary file is among changed files or if no base_ref is given
        base_findings = []
        if changed_files_list:
            changed_set = {p.replace("\\", "/").lower() for p in changed_files_list}
            for f in all_head_findings:
                prim_file = _extract_primary_file(f).lower()
                if any(prim_file.endswith(cp) or cp.endswith(prim_file) for cp in changed_set):
                    new_findings.append(f)
                else:
                    existing_findings.append(f)
        else:
            # If no base_ref, all findings are considered in-scope for head
            new_findings = list(all_head_findings)

    # 6. Quality Gate Evaluation
    gate_verdict, gate_violations, gate_explanation = evaluate_quality_gate(
        new_findings=new_findings,
        all_findings=all_head_findings,
        gate_config=gate_config,
    )

    return PRAnalysisResult(
        project_path=str(root),
        base_ref=base_ref,
        head_ref=head_ref,
        base_sha=base_sha,
        head_sha=head_sha,
        base_scan_available=base_scan_available,
        head_findings=all_head_findings,
        base_findings=base_findings,
        new_findings=new_findings,
        existing_findings=existing_findings,
        resolved_findings=resolved_findings,
        database_findings=db_findings,
        root_causes=root_causes,
        change_impact=change_impact,
        verification=verification_report,
        gate_mode=gate_config.mode,
        gate_verdict=gate_verdict,
        gate_violations=gate_violations,
        gate_explanation=gate_explanation,
        unverified_areas=unverified_areas,
        total_files_scanned=total_files,
        frontend_calls_count=frontend_calls,
        backend_routes_count=backend_routes,
    )
