"""GhostFlow Cloud Scan Execution, Detail, and Persistence Endpoints."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..auth.dependencies import get_authenticated_db, get_current_user
from ..auth.models import AuthenticatedUser
from ..db.models import Finding, Project, RootCause, Scan, ScanGraph
from ..remote_scanner import (
    ConcurrencyLimitError,
    get_remote_resource_limits,
    scan_remote_github_repository,
    validate_github_url,
)
from .persistence import save_cloud_scan
from .schemas import (
    CloudScanRequest,
    FindingResponse,
    RootCauseResponse,
    ScanDetailResponse,
    ScanGraphResponse,
    ScanSummaryResponse,
)

logger = logging.getLogger("ghostflow.cloud.scans")

cloud_scans_router = APIRouter(prefix="/api/cloud", tags=["cloud-scans"])


def _find_scan(scan_identifier: str, user_id: uuid.UUID, db: Session) -> Scan:
    """Find a scan by UUID or human-readable scan_id, strictly scoped to user_id."""
    # Try as UUID first
    try:
        scan_uuid = uuid.UUID(str(scan_identifier))
        scan = db.query(Scan).filter(Scan.id == scan_uuid, Scan.user_id == user_id).first()
        if scan:
            return scan
    except (ValueError, AttributeError):
        pass

    # Try as human-readable scan_id (e.g. scan_20261101_123456_abcdef12)
    scan = db.query(Scan).filter(Scan.scan_id == scan_identifier, Scan.user_id == user_id).first()
    if scan:
        return scan

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")


def _scan_to_summary(s: Scan) -> ScanSummaryResponse:
    return ScanSummaryResponse(
        id=str(s.id),
        scan_id=s.scan_id,
        project_id=str(s.project_id),
        user_id=str(s.user_id),
        scan_mode=s.scan_mode,
        status=s.status,
        scanner_version=getattr(s, "scanner_version", None),
        project_path=s.project_path,
        commit_hash=s.commit_hash,
        branch=s.branch,
        frontend_calls=s.frontend_calls,
        backend_routes=s.backend_routes,
        findings_count=s.findings_count,
        high_count=s.high_count,
        medium_count=s.medium_count,
        low_count=s.low_count,
        duration_ms=s.duration_ms,
        error_message=s.error_message,
        created_at=s.created_at.isoformat() if s.created_at else "",
        completed_at=s.completed_at.isoformat() if s.completed_at else None,
    )


def _scan_to_detail(scan: Scan, db: Session) -> ScanDetailResponse:
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    root_causes = db.query(RootCause).filter(RootCause.scan_id == scan.id).order_by(RootCause.suggested_order.asc()).all()
    graph = db.query(ScanGraph).filter(ScanGraph.scan_id == scan.id).first()

    findings_resp = [
        FindingResponse(
            id=str(f.id),
            finding_uid=f.finding_uid,
            scan_id=str(f.scan_id),
            rule_id=f.rule_id,
            category=f.category,
            severity=f.severity,
            confidence=f.confidence,
            title=f.title,
            message=f.message,
            recommendation=f.recommendation,
            evidence=f.evidence_json or [],
            details=f.details_json or {},
            node_ids=f.node_ids_json or [],
            edge_ids=f.edge_ids_json or [],
            created_at=f.created_at.isoformat() if f.created_at else "",
        )
        for f in findings
    ]

    root_causes_resp = [
        RootCauseResponse(
            id=str(rc.id),
            candidate_id=rc.candidate_id,
            scan_id=str(rc.scan_id),
            title=rc.title,
            category=rc.category,
            state=rc.state,
            confidence=rc.confidence,
            severity=rc.severity,
            description=rc.description,
            recommended_action=rc.recommended_action,
            suggested_order=rc.suggested_order,
            impact_summary=rc.impact_summary,
            shared_entity=rc.shared_entity,
            finding_ids=rc.finding_ids_json or [],
            affected_components=rc.affected_components_json or [],
            evidence=rc.evidence_json or [],
            node_ids=rc.node_ids_json or [],
            edge_ids=rc.edge_ids_json or [],
            created_at=rc.created_at.isoformat() if rc.created_at else "",
        )
        for rc in root_causes
    ]

    graph_resp = (
        ScanGraphResponse(
            id=str(graph.id),
            scan_id=str(graph.scan_id),
            node_count=graph.node_count,
            edge_count=graph.edge_count,
            nodes=graph.nodes_json or [],
            edges=graph.edges_json or [],
            metadata=graph.metadata_json or {},
        )
        if graph
        else None
    )

    summary = _scan_to_summary(scan)
    return ScanDetailResponse(
        **summary.model_dump(),
        findings=findings_resp,
        root_causes=root_causes_resp,
        graph=graph_resp,
        resource_limits=get_remote_resource_limits(),
    )


@cloud_scans_router.post("/projects/{project_id}/scans", response_model=ScanDetailResponse)
def trigger_cloud_scan(
    project_id: str,
    request: CloudScanRequest = CloudScanRequest(),
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> ScanDetailResponse:
    """Trigger an isolated remote GitHub scan and persist the results to PostgreSQL."""
    try:
        proj_uuid = uuid.UUID(str(project_id))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")

    project = db.query(Project).filter(Project.id == proj_uuid, Project.user_id == user.id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")

    target_repo = request.repo_url or project.repository_url
    if not target_repo:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Project has no repository URL configured. Please specify a public GitHub repository URL.",
        )

    try:
        validate_github_url(target_repo)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    openapi_path = request.openapi_path or project.default_openapi_path
    start_time = time.time()

    try:
        report_data = scan_remote_github_repository(
            repo_url=target_repo,
            openapi_path=openapi_path,
            auto_detect_openapi=request.auto_detect_openapi,
            timeout_seconds=request.timeout_seconds,
        )
    except ConcurrencyLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": "5"},
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except TimeoutError as exc:
        raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Cloud scan failed for repo %s: %s", target_repo, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Remote scan failed: {exc}",
        ) from exc

    duration_ms = int((time.time() - start_time) * 1000)

    # Persist results to PostgreSQL
    scan = save_cloud_scan(
        report_data=report_data,
        project=project,
        user_id=user.id,
        db=db,
        duration_ms=duration_ms,
        scan_mode=request.scan_mode,
    )

    return _scan_to_detail(scan, db)


@cloud_scans_router.get("/scans", response_model=list[dict[str, Any]])
def list_user_scans(
    limit: int = Query(default=100, ge=1, le=500),
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> list[dict[str, Any]]:
    """List recent cloud scans owned by the authenticated user."""
    scans = (
        db.query(Scan)
        .filter(Scan.user_id == user.id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": str(s.id),
            "scan_id": s.scan_id,
            "project_id": str(s.project_id),
            "scan_mode": s.scan_mode,
            "status": s.status,
            "scanner_version": getattr(s, "scanner_version", None),
            "findings_count": s.findings_count,
            "high_count": s.high_count,
            "medium_count": s.medium_count,
            "low_count": s.low_count,
            "duration_ms": s.duration_ms,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in scans
    ]


@cloud_scans_router.get("/scans/{scan_id}", response_model=ScanDetailResponse)
def get_scan_detail(
    scan_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> ScanDetailResponse:
    """Retrieve full scan report, findings, root causes, and graph by scan ID."""
    scan = _find_scan(scan_id, user.id, db)
    return _scan_to_detail(scan, db)


@cloud_scans_router.get("/scans/{scan_id}/findings", response_model=list[FindingResponse])
def get_scan_findings(
    scan_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> list[FindingResponse]:
    """Retrieve all findings emitted by a specific scan."""
    scan = _find_scan(scan_id, user.id, db)
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    return [
        FindingResponse(
            id=str(f.id),
            finding_uid=f.finding_uid,
            scan_id=str(f.scan_id),
            rule_id=f.rule_id,
            category=f.category,
            severity=f.severity,
            confidence=f.confidence,
            title=f.title,
            message=f.message,
            recommendation=f.recommendation,
            evidence=f.evidence_json or [],
            details=f.details_json or {},
            node_ids=f.node_ids_json or [],
            edge_ids=f.edge_ids_json or [],
            created_at=f.created_at.isoformat() if f.created_at else "",
        )
        for f in findings
    ]


@cloud_scans_router.get("/scans/{scan_id}/graph", response_model=ScanGraphResponse | None)
def get_scan_graph(
    scan_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> ScanGraphResponse | None:
    """Retrieve the dependency graph for a specific scan."""
    scan = _find_scan(scan_id, user.id, db)
    graph = db.query(ScanGraph).filter(ScanGraph.scan_id == scan.id).first()
    if not graph:
        return None
    return ScanGraphResponse(
        id=str(graph.id),
        scan_id=str(graph.scan_id),
        node_count=graph.node_count,
        edge_count=graph.edge_count,
        nodes=graph.nodes_json or [],
        edges=graph.edges_json or [],
        metadata=graph.metadata_json or {},
    )


@cloud_scans_router.delete("/scans/{scan_id}")
def delete_scan(
    scan_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> dict[str, Any]:
    """Delete a scan and cascade-delete its findings, root causes, and graph."""
    scan = _find_scan(scan_id, user.id, db)
    scan_id_str = scan.scan_id
    db.delete(scan)
    db.flush()
    return {"status": "deleted", "scan_id": scan_id_str}

