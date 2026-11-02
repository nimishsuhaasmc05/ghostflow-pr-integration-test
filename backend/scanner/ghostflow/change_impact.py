"""GhostFlow Git-Aware Change Impact Analysis.

Tracks changed files via Git (when available) and traces relationships to:
- Frontend API calls and components
- Backend API routes and handlers
- Schema models and database definitions
- Potentially affected contracts (marked as potential impact, NEVER confirmed defects)
- Relevant test suites to run

Guarantees:
- Safe subprocess execution with strict timeouts.
- Graceful fallback when Git is absent or workspace is not a Git repository.
- Pure static dependency analysis.
- Clear distinction between confirmed defects and candidate impact propagation.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
from typing import Any
from pydantic import BaseModel, Field

from .models import ApiCall, ApiRoute, SchemaModel


class ChangedFile(BaseModel):
    path: str
    status: str  # "modified", "added", "deleted", "renamed", "untracked"
    old_path: str | None = None
    role: str = "other"  # "frontend", "backend", "database", "config", "test", "docs", "other"


class AffectedRoute(BaseModel):
    method: str
    path: str
    file: str
    line: int
    change_type: str  # "direct" (file changed) or "indirect" (model changed)


class AffectedCall(BaseModel):
    method: str
    path: str
    file: str
    line: int
    change_type: str  # "direct" (caller changed) or "downstream" (target route changed)


class ContractRisk(BaseModel):
    title: str
    risk_level: str  # "high", "medium", "low"
    potential_impact: str
    uncertainty_note: str = (
        "Candidate impact propagation identified statically. "
        "Possible impact does not constitute a confirmed defect until verified by scanner or tests."
    )
    affected_endpoints: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)


class ChangeImpactReport(BaseModel):
    git_available: bool
    is_git_repo: bool = False
    branch: str | None = None
    base_ref: str | None = None
    changed_files: list[ChangedFile] = Field(default_factory=list)
    affected_routes: list[AffectedRoute] = Field(default_factory=list)
    affected_calls: list[AffectedCall] = Field(default_factory=list)
    affected_models: list[str] = Field(default_factory=list)
    broken_contract_risks: list[ContractRisk] = Field(default_factory=list)
    suggested_tests: list[str] = Field(default_factory=list)
    risk_level: str = "low"  # "low", "medium", "high"
    risk_summary: str = ""
    uncertainty_note: str = (
        "Change impact analysis maps potential propagation pathways based on static dependencies. "
        "Candidate risks are not confirmed defects."
    )


def _classify_role(path_str: str) -> str:
    lower = path_str.lower().replace("\\", "/")
    if any(p in lower for p in ["/test", "/tests", "/__tests__", "test_", ".test.", ".spec."]):
        return "test"
    if any(p in lower for p in ["alembic", "migrations", "/db/", "/models/", "models.py", "schema.prisma"]):
        return "database"
    if lower.endswith((".json", ".toml", ".yaml", ".yml", ".ini", ".env", ".env.example", "dockerfile")):
        return "config"
    if lower.endswith((".tsx", ".jsx", ".vue", ".svelte", ".css", ".scss", ".html")):
        return "frontend"
    if lower.endswith((".py", ".go", ".rs", ".java", ".rb", ".php")):
        return "backend"
    if lower.endswith((".ts", ".js")):
        if any(f in lower for f in ["front", "client", "app", "ui", "web", "src"]):
            return "frontend"
        return "backend"
    if lower.endswith((".md", ".txt", ".rst")):
        return "docs"
    return "other"


def _run_git_cmd(args: list[str], cwd: Path, timeout: float = 4.0) -> tuple[int, str, str]:
    """Execute git command safely without hanging."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return proc.returncode, proc.stdout.rstrip("\r\n"), proc.stderr.rstrip("\r\n")
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError) as e:
        return -1, "", str(e)


def _normalize_rel(path_str: str) -> str:
    return path_str.replace("\\", "/").strip().lstrip("./")


def analyze_change_impact(
    root: Path,
    base_ref: str | None = None,
    calls: list[ApiCall] | None = None,
    routes: list[ApiRoute] | None = None,
    models: dict[str, SchemaModel] | None = None,
) -> ChangeImpactReport:
    """Analyze change impact for a project root against Git status or base branch.

    Gracefully falls back if Git is unavailable or root is not a Git repo.
    """
    if calls is None:
        calls = []
    if routes is None:
        routes = []
    if models is None:
        models = {}

    # Check if Git executable is available
    ret, out, _ = _run_git_cmd(["--version"], cwd=root)
    if ret != 0:
        return ChangeImpactReport(
            git_available=False,
            risk_summary="Git is not installed or not accessible in PATH.",
        )

    # Check if inside git work tree
    ret, out, _ = _run_git_cmd(["rev-parse", "--is-inside-work-tree"], cwd=root)
    if ret != 0 or out != "true":
        return ChangeImpactReport(
            git_available=True,
            is_git_repo=False,
            risk_summary="Project directory is not inside a Git repository.",
        )

    # Get current branch
    ret, branch, _ = _run_git_cmd(["rev-parse", "--abbrev-ref", "HEAD"], cwd=root)
    current_branch = branch if ret == 0 else "unknown"

    changed_files_map: dict[str, ChangedFile] = {}

    # 1. Parse uncommitted changes from git status
    ret, status_out, _ = _run_git_cmd(["status", "--porcelain=v1", "-uall"], cwd=root)
    if ret == 0 and status_out:
        for line in status_out.splitlines():
            line = line.rstrip()
            if len(line) < 3:
                continue
            xy = line[:2]
            filename_part = line[2:].strip()
            # Handle rename 'old -> new'
            old_path = None
            if " -> " in filename_part:
                parts = filename_part.split(" -> ")
                old_path = _normalize_rel(parts[0])
                rel_path = _normalize_rel(parts[1])
            else:
                rel_path = _normalize_rel(filename_part)

            # Strip quotation marks if git output quotes paths with special characters
            rel_path = rel_path.strip('"')
            if old_path:
                old_path = old_path.strip('"')

            status = "modified"
            if xy == "??":
                status = "untracked"
            elif "A" in xy:
                status = "added"
            elif "D" in xy:
                status = "deleted"
            elif "R" in xy:
                status = "renamed"

            role = _classify_role(rel_path)
            changed_files_map[rel_path] = ChangedFile(
                path=rel_path,
                status=status,
                old_path=old_path,
                role=role,
            )

    # 2. If base_ref is specified (e.g. "main" or "origin/main"), diff against base_ref
    if base_ref:
        ret, diff_out, _ = _run_git_cmd(["diff", "--name-status", f"{base_ref}...HEAD"], cwd=root)
        if ret == 0 and diff_out:
            for line in diff_out.splitlines():
                parts = line.strip().split("\t")
                if not parts:
                    continue
                code = parts[0]
                status = "modified"
                old_path = None
                if code.startswith("A"):
                    status = "added"
                    rel_path = _normalize_rel(parts[1])
                elif code.startswith("D"):
                    status = "deleted"
                    rel_path = _normalize_rel(parts[1])
                elif code.startswith("R") and len(parts) >= 3:
                    status = "renamed"
                    old_path = _normalize_rel(parts[1])
                    rel_path = _normalize_rel(parts[2])
                else:
                    rel_path = _normalize_rel(parts[-1])

                rel_path = rel_path.strip('"')
                if old_path:
                    old_path = old_path.strip('"')

                role = _classify_role(rel_path)
                changed_files_map[rel_path] = ChangedFile(
                    path=rel_path,
                    status=status,
                    old_path=old_path,
                    role=role,
                )

    changed_files = list(changed_files_map.values())
    changed_path_set = {f.path for f in changed_files}

    # 3. Correlate with API Routes
    affected_routes: list[AffectedRoute] = []
    affected_route_keys: set[tuple[str, str]] = set()

    for r in routes:
        norm_r_file = _normalize_rel(r.file)
        if any(norm_r_file.endswith(cp) or cp.endswith(norm_r_file) for cp in changed_path_set):
            affected_routes.append(AffectedRoute(
                method=r.method,
                path=r.path,
                file=r.file,
                line=r.line,
                change_type="direct",
            ))
            affected_route_keys.add((r.method.upper(), r.path))

    # 4. Correlate with API Calls (Frontend)
    affected_calls: list[AffectedCall] = []
    for c in calls:
        norm_c_file = _normalize_rel(c.file)
        # Direct impact: frontend file containing call was modified
        if any(norm_c_file.endswith(cp) or cp.endswith(norm_c_file) for cp in changed_path_set):
            affected_calls.append(AffectedCall(
                method=c.method,
                path=c.path,
                file=c.file,
                line=c.line,
                change_type="direct",
            ))
        # Downstream impact: backend route called by frontend was modified
        elif (c.method.upper(), c.path) in affected_route_keys:
            affected_calls.append(AffectedCall(
                method=c.method,
                path=c.path,
                file=c.file,
                line=c.line,
                change_type="downstream",
            ))

    # 5. Correlate with Schema Models
    affected_models: list[str] = []
    for model_name, m in models.items():
        norm_m_file = _normalize_rel(m.file)
        if any(norm_m_file.endswith(cp) or cp.endswith(norm_m_file) for cp in changed_path_set):
            affected_models.append(model_name)

    # 6. Analyze Potential Contract Risks
    contract_risks: list[ContractRisk] = []

    # Risk 1: Routes changed with downstream frontend callers
    downstream_calls = [ac for ac in affected_calls if ac.change_type == "downstream"]
    if downstream_calls:
        ep_list = sorted({f"{c.method} {c.path}" for c in downstream_calls})
        contract_risks.append(ContractRisk(
            title=f"Backend routes modified with {len(downstream_calls)} downstream frontend callers",
            risk_level="high",
            potential_impact=(
                "Changes to backend handler logic or parameters may affect frontend API consumption. "
                "Verify response schemas and HTTP status codes."
            ),
            affected_endpoints=ep_list,
            files=sorted({c.file for c in downstream_calls}),
        ))

    # Risk 2: Schema models modified
    if affected_models:
        contract_risks.append(ContractRisk(
            title=f"Schema models modified ({', '.join(affected_models[:3])}{'...' if len(affected_models) > 3 else ''})",
            risk_level="medium",
            potential_impact=(
                "Changes to model fields, types, or nullability could alter serialization contracts. "
                "Check client data parsing and validation."
            ),
            affected_endpoints=[],
            files=sorted({m.file for name, m in models.items() if name in affected_models}),
        ))

    # Risk 3: Database / Migration files changed
    db_changes = [f for f in changed_files if f.role == "database"]
    if db_changes:
        contract_risks.append(ContractRisk(
            title=f"Database migrations or models altered ({len(db_changes)} files)",
            risk_level="high",
            potential_impact=(
                "Database schema modifications require synchronization with ORM models and migrations. "
                "Inspect column types and nullable constraints."
            ),
            affected_endpoints=[],
            files=[f.path for f in db_changes],
        ))

    # 7. Identify Suggested Tests
    suggested_tests_set: set[str] = set()

    # Collect existing test files in project
    for root_dir, dirs, files in os.walk(root):
        # Skip excluded dirs
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "dist", "build", "__pycache__")]
        for file_name in files:
            lower_name = file_name.lower()
            if lower_name.startswith("test_") or lower_name.endswith(("_test.py", ".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx")):
                full_test_path = _normalize_rel(str(Path(root_dir, file_name).relative_to(root)))

                # Match against changed files by basename
                for cf in changed_files:
                    stem = Path(cf.path).stem.replace(".test", "").replace(".spec", "")
                    if stem and len(stem) > 2 and stem.lower() in lower_name:
                        suggested_tests_set.add(full_test_path)

                # If test itself changed, include it
                if full_test_path in changed_path_set:
                    suggested_tests_set.add(full_test_path)

    # 8. Compute Overall Risk Level
    risk_level = "low"
    if any(cr.risk_level == "high" for cr in contract_risks):
        risk_level = "high"
    elif any(cr.risk_level == "medium" for cr in contract_risks) or len(affected_routes) > 2 or len(affected_calls) > 3:
        risk_level = "medium"
    elif len(changed_files) == 0:
        risk_level = "low"

    summary_parts = []
    if len(changed_files) == 0:
        summary_parts.append("Workspace is clean; no uncommitted changes.")
    else:
        summary_parts.append(f"{len(changed_files)} changed files detected across {len(affected_routes)} routes and {len(affected_calls)} call sites.")
        if contract_risks:
            summary_parts.append(f"{len(contract_risks)} candidate propagation areas identified.")

    return ChangeImpactReport(
        git_available=True,
        is_git_repo=True,
        branch=current_branch,
        base_ref=base_ref,
        changed_files=changed_files,
        affected_routes=affected_routes,
        affected_calls=affected_calls,
        affected_models=affected_models,
        broken_contract_risks=contract_risks,
        suggested_tests=sorted(suggested_tests_set),
        risk_level=risk_level,
        risk_summary=" ".join(summary_parts),
    )
