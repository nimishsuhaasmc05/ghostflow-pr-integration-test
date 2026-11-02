from __future__ import annotations
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .models import (
    Finding,
    IdentityChange,
    ScanComparisonResult,
    ScanHistoryDetail,
    ScanHistorySummary,
    ScanReport,
    SeverityBreakdown,
)

SCHEMA_VERSION = 1
SCAN_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{8,64}$")


def get_history_db_path() -> Path:
    """Resolve the SQLite database path for persistent scan history."""
    env_db = os.environ.get("GHOSTFLOW_HISTORY_DB")
    if env_db:
        p = Path(env_db).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    base_dir = Path(os.environ.get("GHOSTFLOW_HISTORY_DIR", str(Path.home() / ".ghostflow"))).expanduser().resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / "history.db"


def init_history_db(db_path: Path | None = None) -> sqlite3.Connection:
    """Initialize SQLite database with scan_history table and index."""
    target_path = db_path or get_history_db_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path), timeout=15.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                scan_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                project_path TEXT NOT NULL,
                frontend_calls INTEGER NOT NULL,
                backend_routes INTEGER NOT NULL,
                findings_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                medium_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL,
                schema_version INTEGER NOT NULL DEFAULT 1,
                report_json TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp
            ON scan_history(timestamp DESC);
        """)
    return conn


def save_scan(
    report_data: ScanReport | dict[str, Any],
    db_path: Path | None = None,
    scan_id: str | None = None,
    timestamp: str | None = None,
) -> ScanHistorySummary:
    """Save a scan report to persistent history."""
    if isinstance(report_data, dict):
        report = ScanReport(**report_data)
    else:
        report = report_data

    # Generate validated scan_id and UTC timestamp if not provided
    generated_id = scan_id or f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    if not SCAN_ID_RE.match(generated_id):
        raise ValueError(f"Invalid scan ID format: '{generated_id}'")

    generated_timestamp = timestamp or datetime.now(timezone.utc).isoformat()

    report.scan_id = generated_id
    report.timestamp = generated_timestamp

    findings = report.findings
    high_count = sum(1 for f in findings if f.severity == "high")
    medium_count = sum(1 for f in findings if f.severity == "medium")
    low_count = sum(1 for f in findings if f.severity == "low")

    report_json = report.model_dump_json()

    conn = init_history_db(db_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_history (
                    scan_id, timestamp, project_path, frontend_calls, backend_routes,
                    findings_count, high_count, medium_count, low_count, schema_version, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    generated_id,
                    generated_timestamp,
                    report.project_path,
                    report.frontend_calls,
                    report.backend_routes,
                    len(findings),
                    high_count,
                    medium_count,
                    low_count,
                    SCHEMA_VERSION,
                    report_json,
                ),
            )
    finally:
        conn.close()

    return ScanHistorySummary(
        scan_id=generated_id,
        timestamp=generated_timestamp,
        project_path=report.project_path,
        frontend_calls=report.frontend_calls,
        backend_routes=report.backend_routes,
        findings_count=len(findings),
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        schema_version=SCHEMA_VERSION,
    )


def list_scans(
    db_path: Path | None = None,
    limit: int = 100,
    project_path: str | None = None,
) -> list[ScanHistorySummary]:
    """List saved scans ordered newest first."""
    conn = init_history_db(db_path)
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if project_path:
            cursor.execute(
                """
                SELECT scan_id, timestamp, project_path, frontend_calls, backend_routes,
                       findings_count, high_count, medium_count, low_count, schema_version
                FROM scan_history
                WHERE project_path = ?
                ORDER BY timestamp DESC, rowid DESC
                LIMIT ?
                """,
                (project_path, max(1, min(limit, 500))),
            )
        else:
            cursor.execute(
                """
                SELECT scan_id, timestamp, project_path, frontend_calls, backend_routes,
                       findings_count, high_count, medium_count, low_count, schema_version
                FROM scan_history
                ORDER BY timestamp DESC, rowid DESC
                LIMIT ?
                """,
                (max(1, min(limit, 500)),),
            )
        rows = cursor.fetchall()
        return [
            ScanHistorySummary(
                scan_id=row["scan_id"],
                timestamp=row["timestamp"],
                project_path=row["project_path"],
                frontend_calls=row["frontend_calls"],
                backend_routes=row["backend_routes"],
                findings_count=row["findings_count"],
                high_count=row["high_count"],
                medium_count=row["medium_count"],
                low_count=row["low_count"],
                schema_version=row["schema_version"],
            )
            for row in rows
        ]
    finally:
        conn.close()


def get_scan(scan_id: str, db_path: Path | None = None) -> ScanHistoryDetail | None:
    """Retrieve full scan history report by scan ID."""
    if not SCAN_ID_RE.match(scan_id):
        raise ValueError(f"Invalid scan ID format: '{scan_id}'")

    conn = init_history_db(db_path)
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT scan_id, timestamp, project_path, frontend_calls, backend_routes,
                   findings_count, high_count, medium_count, low_count, schema_version, report_json
            FROM scan_history
            WHERE scan_id = ?
            """,
            (scan_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        try:
            report_dict = json.loads(row["report_json"])
            report = ScanReport(**report_dict)
        except Exception as exc:
            raise ValueError(f"Corrupted scan report JSON in database: {exc}") from exc

        return ScanHistoryDetail(
            scan_id=row["scan_id"],
            timestamp=row["timestamp"],
            project_path=row["project_path"],
            frontend_calls=row["frontend_calls"],
            backend_routes=row["backend_routes"],
            findings_count=row["findings_count"],
            high_count=row["high_count"],
            medium_count=row["medium_count"],
            low_count=row["low_count"],
            schema_version=row["schema_version"],
            report=report,
        )
    finally:
        conn.close()


def delete_scan(scan_id: str, db_path: Path | None = None) -> bool:
    """Delete a scan history entry by scan ID."""
    if not SCAN_ID_RE.match(scan_id):
        raise ValueError(f"Invalid scan ID format: '{scan_id}'")

    conn = init_history_db(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scan_history WHERE scan_id = ?", (scan_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()


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


def _calc_severity(findings: list[Finding]) -> SeverityBreakdown:
    return SeverityBreakdown(
        high=sum(1 for f in findings if f.severity == "high"),
        medium=sum(1 for f in findings if f.severity == "medium"),
        low=sum(1 for f in findings if f.severity == "low"),
    )


def compare_reports(
    older_report: ScanReport,
    newer_report: ScanReport,
    older_scan_id: str = "",
    newer_scan_id: str = "",
    older_timestamp: str = "",
    newer_timestamp: str = "",
) -> ScanComparisonResult:
    """Compare two scan reports with stable semantic identity tracking."""
    older_findings = list(older_report.findings)
    newer_findings = list(newer_report.findings)

    consumed_older: set[int] = set()
    consumed_newer: set[int] = set()

    still_existing_findings: list[Finding] = []
    identity_changes: list[IdentityChange] = []

    # Stage 1: Exact finding ID matching
    newer_by_id: dict[str, list[int]] = {}
    for idx, n in enumerate(newer_findings):
        newer_by_id.setdefault(n.id, []).append(idx)

    for o_idx, o in enumerate(older_findings):
        candidates = newer_by_id.get(o.id, [])
        matched_n_idx = None
        for n_idx in candidates:
            if n_idx not in consumed_newer:
                matched_n_idx = n_idx
                break
        if matched_n_idx is not None:
            consumed_older.add(o_idx)
            consumed_newer.add(matched_n_idx)
            still_existing_findings.append(newer_findings[matched_n_idx])

    # Stage 2: Semantic defect matching (same rule, method, normalized_path, slot)
    for o_idx, o in enumerate(older_findings):
        if o_idx in consumed_older:
            continue
        o_key = _get_semantic_key(o)
        matched_n_idx = None
        for n_idx, n in enumerate(newer_findings):
            if n_idx in consumed_newer:
                continue
            if n.rule_id == o.rule_id and _get_semantic_key(n) == o_key:
                matched_n_idx = n_idx
                break

        if matched_n_idx is not None:
            consumed_older.add(o_idx)
            consumed_newer.add(matched_n_idx)
            matched_n = newer_findings[matched_n_idx]
            still_existing_findings.append(matched_n)

            reason_desc = (
                f"Defect {o.rule_id} persists across scan versions: "
                f"finding ID shifted from {o.id} to {matched_n.id} "
                f"due to parameter renaming, evidence changes, or path updates."
            )
            identity_changes.append(
                IdentityChange(
                    old_id=o.id,
                    new_id=matched_n.id,
                    rule_id=o.rule_id,
                    reason=reason_desc,
                    details={
                        "old_details": o.details,
                        "new_details": matched_n.details,
                        "endpoint": f"{o_key[1]} {o_key[2]}",
                        "slot": o_key[3],
                    },
                )
            )

    # Stage 3: Resolved findings (in older report, absent from newer report)
    resolved_findings = [o for idx, o in enumerate(older_findings) if idx not in consumed_older]

    # Stage 4: New findings (in newer report, absent from older report)
    new_findings = [n for idx, n in enumerate(newer_findings) if idx not in consumed_newer]

    different_projects = (older_report.project_path != newer_report.project_path)

    return ScanComparisonResult(
        older_scan_id=older_scan_id or older_report.scan_id or "",
        older_timestamp=older_timestamp or older_report.timestamp or "",
        older_project_path=older_report.project_path,
        newer_scan_id=newer_scan_id or newer_report.scan_id or "",
        newer_timestamp=newer_timestamp or newer_report.timestamp or "",
        newer_project_path=newer_report.project_path,
        different_projects=different_projects,
        older_findings_count=len(older_findings),
        newer_findings_count=len(newer_findings),
        resolved_count=len(resolved_findings),
        still_existing_count=len(still_existing_findings),
        new_count=len(new_findings),
        older_severity=_calc_severity(older_findings),
        newer_severity=_calc_severity(newer_findings),
        resolved_findings=resolved_findings,
        still_existing_findings=still_existing_findings,
        new_findings=new_findings,
        identity_changes=identity_changes,
    )


def compare_historical_scans(
    older_scan_id: str,
    newer_scan_id: str,
    db_path: Path | None = None,
    auto_order_by_timestamp: bool = True,
) -> ScanComparisonResult:
    """Load two saved scans from persistent SQLite history and compare findings."""
    if not SCAN_ID_RE.match(older_scan_id):
        raise ValueError(f"Invalid scan ID format: '{older_scan_id}'")
    if not SCAN_ID_RE.match(newer_scan_id):
        raise ValueError(f"Invalid scan ID format: '{newer_scan_id}'")

    older_detail = get_scan(older_scan_id, db_path=db_path)
    if not older_detail:
        raise KeyError(f"Scan history entry '{older_scan_id}' not found")

    newer_detail = get_scan(newer_scan_id, db_path=db_path)
    if not newer_detail:
        raise KeyError(f"Scan history entry '{newer_scan_id}' not found")

    # If auto-ordering is enabled and older is chronologically after newer, swap them
    if auto_order_by_timestamp and older_detail.timestamp > newer_detail.timestamp:
        older_detail, newer_detail = newer_detail, older_detail

    return compare_reports(
        older_report=older_detail.report,
        newer_report=newer_detail.report,
        older_scan_id=older_detail.scan_id,
        newer_scan_id=newer_detail.scan_id,
        older_timestamp=older_detail.timestamp,
        newer_timestamp=newer_detail.timestamp,
    )

