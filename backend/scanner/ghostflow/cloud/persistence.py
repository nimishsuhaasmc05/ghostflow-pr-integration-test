"""GhostFlow Cloud Persistence Layer.

Persists completed scan results (metadata, findings, root causes, dependency graphs)
to PostgreSQL tables while maintaining multi-tenant composite ownership isolation.
Raw source code files are NEVER persisted to the database.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..db.models import Finding, Project, RootCause, Scan, ScanGraph
from ..db.sanitizer import (
    sanitize_details_dict,
    sanitize_evidence_list,
    sanitize_project_path,
    sanitize_repository_url,
)

logger = logging.getLogger("ghostflow.cloud.persistence")


def save_cloud_scan(
    report_data: dict[str, Any],
    project: Project,
    user_id: uuid.UUID,
    db: Session,
    duration_ms: int | None = None,
    commit_hash: str | None = None,
    branch: str | None = None,
    scan_mode: str = "standard",
) -> Scan:
    """Persist a completed scan report into PostgreSQL.

    Guarantees:
    - User ID is derived exclusively from the verified JWT identity.
    - Project ownership is enforced via composite constraints.
    - Evidence snippets and details are sanitized against credentials/paths.
    - Findings, root causes, and graph components are persisted transactionally.
    """
    scan_uuid = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)
    now_str = now_utc.strftime("%Y%m%d_%H%M%S")
    scan_id_str = report_data.get("scan_id") or f"scan_{now_str}_{scan_uuid.hex[:8]}"

    # Project path sanitization
    raw_path = report_data.get("project_path") or report_data.get("repo_url") or project.repository_url or project.name
    if report_data.get("is_remote_github") or (raw_path and raw_path.startswith("https://github.com")):
        safe_path = sanitize_repository_url(raw_path) or raw_path
    else:
        safe_path = sanitize_project_path(raw_path)

    raw_findings = report_data.get("findings", [])
    high_count = 0
    medium_count = 0
    low_count = 0

    for f in raw_findings:
        sev = f.severity if hasattr(f, "severity") else f.get("severity")
        if sev == "high":
            high_count += 1
        elif sev == "medium":
            medium_count += 1
        elif sev == "low":
            low_count += 1

    scan = Scan(
        id=scan_uuid,
        scan_id=scan_id_str,
        project_id=project.id,
        user_id=user_id,
        scan_mode=scan_mode,
        status="completed",
        scanner_version="0.3.0",
        project_path=safe_path,
        commit_hash=commit_hash or report_data.get("commit_hash"),
        branch=branch or report_data.get("branch"),
        frontend_calls=int(report_data.get("frontend_calls", 0)),
        backend_routes=int(report_data.get("backend_routes", 0)),
        findings_count=len(raw_findings),
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        duration_ms=duration_ms or (int(report_data.get("clone_duration_seconds", 0) * 1000) if "clone_duration_seconds" in report_data else None),
        error_message=None,
        created_at=now_utc,
        completed_at=now_utc,
    )
    db.add(scan)
    db.flush()

    # 1. Findings
    for f in raw_findings:
        if isinstance(f, dict):
            finding_uid = f.get("id") or str(uuid.uuid4())
            rule_id = f.get("rule_id", "GEN001")
            category = f.get("category", "api")
            severity = f.get("severity", "medium")
            confidence = float(f.get("confidence", 0.80))
            title = f.get("title", "Finding")
            message = f.get("message", "")
            recommendation = f.get("recommendation", "")
            evidence_raw = f.get("evidence", [])
            details_raw = f.get("details", {})
            node_ids_raw = f.get("node_ids", [])
            edge_ids_raw = f.get("edge_ids", [])
        else:
            finding_uid = getattr(f, "id", str(uuid.uuid4()))
            rule_id = getattr(f, "rule_id", "GEN001")
            category = getattr(f, "category", "api")
            severity = getattr(f, "severity", "medium")
            confidence = float(getattr(f, "confidence", 0.80))
            title = getattr(f, "title", "Finding")
            message = getattr(f, "message", "")
            recommendation = getattr(f, "recommendation", "")
            evidence_raw = [e.model_dump() if hasattr(e, "model_dump") else e for e in getattr(f, "evidence", [])]
            details_raw = getattr(f, "details", {})
            node_ids_raw = getattr(f, "node_ids", [])
            edge_ids_raw = getattr(f, "edge_ids", [])

        finding_row = Finding(
            id=uuid.uuid4(),
            finding_uid=finding_uid,
            scan_id=scan.id,
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=confidence,
            title=title,
            message=message,
            recommendation=recommendation,
            evidence_json=sanitize_evidence_list(evidence_raw),
            details_json=sanitize_details_dict(details_raw),
            node_ids_json=node_ids_raw or [],
            edge_ids_json=edge_ids_raw or [],
            created_at=now_utc,
        )
        db.add(finding_row)

    # 2. Root Causes
    raw_root_causes = report_data.get("root_causes", [])
    for rc in raw_root_causes:
        if isinstance(rc, dict):
            candidate_id = rc.get("id") or str(uuid.uuid4())
            title = rc.get("title", "Root Cause")
            category = rc.get("category", "architectural")
            state = rc.get("state", "LIKELY")
            confidence = float(rc.get("confidence", 0.80))
            severity = rc.get("severity", "medium")
            description = rc.get("description", "")
            recommended_action = rc.get("recommended_action", "")
            suggested_order = int(rc.get("suggested_order", 1))
            impact_summary = rc.get("impact_summary")
            shared_entity = rc.get("shared_entity")
            finding_ids = rc.get("finding_ids", [])
            affected_components = rc.get("affected_components", [])
            evidence = rc.get("evidence", [])
            node_ids = rc.get("node_ids", [])
            edge_ids = rc.get("edge_ids", [])
        else:
            candidate_id = getattr(rc, "id", str(uuid.uuid4()))
            title = getattr(rc, "title", "Root Cause")
            category = getattr(rc, "category", "architectural")
            state = getattr(rc, "state", "LIKELY")
            confidence = float(getattr(rc, "confidence", 0.80))
            severity = getattr(rc, "severity", "medium")
            description = getattr(rc, "description", "")
            recommended_action = getattr(rc, "recommended_action", "")
            suggested_order = int(getattr(rc, "suggested_order", 1))
            impact_summary = getattr(rc, "impact_summary", None)
            shared_entity = getattr(rc, "shared_entity", None)
            finding_ids = getattr(rc, "finding_ids", [])
            affected_components = getattr(rc, "affected_components", [])
            evidence = getattr(rc, "evidence", [])
            node_ids = getattr(rc, "node_ids", [])
            edge_ids = getattr(rc, "edge_ids", [])

        root_cause_row = RootCause(
            id=uuid.uuid4(),
            candidate_id=candidate_id,
            scan_id=scan.id,
            title=title,
            category=category,
            state=state,
            confidence=confidence,
            severity=severity,
            description=description,
            recommended_action=recommended_action,
            suggested_order=suggested_order,
            impact_summary=impact_summary,
            shared_entity=shared_entity,
            finding_ids_json=finding_ids or [],
            affected_components_json=affected_components or [],
            evidence_json=sanitize_evidence_list(evidence),
            node_ids_json=node_ids or [],
            edge_ids_json=edge_ids or [],
            created_at=now_utc,
        )
        db.add(root_cause_row)

    # 3. Dependency Graph
    raw_graph = report_data.get("graph")
    if raw_graph:
        if isinstance(raw_graph, dict):
            nodes = raw_graph.get("nodes", [])
            edges = raw_graph.get("edges", [])
            metadata = raw_graph.get("metadata", {})
        else:
            nodes = [n.model_dump() if hasattr(n, "model_dump") else n for n in getattr(raw_graph, "nodes", [])]
            edges = [e.model_dump() if hasattr(e, "model_dump") else e for e in getattr(raw_graph, "edges", [])]
            metadata = getattr(raw_graph, "metadata", {})

        graph_row = ScanGraph(
            id=uuid.uuid4(),
            scan_id=scan.id,
            node_count=len(nodes),
            edge_count=len(edges),
            nodes_json=nodes,
            edges_json=edges,
            metadata_json=metadata or {},
            created_at=now_utc,
        )
        db.add(graph_row)

    db.flush()
    logger.info("Successfully persisted cloud scan %s (%s) for project %s", scan.id, scan.scan_id, project.id)
    return scan

