"""GhostFlow Cloud Scan Comparison Endpoints."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..auth.dependencies import get_authenticated_db, get_current_user
from ..auth.models import AuthenticatedUser
from ..db.models import Finding, Project, Scan, ScanComparison
from ..history import compare_reports
from ..models import Evidence, Finding as ModelFinding, ScanReport
from .scans import _find_scan
from .schemas import ComparisonCreateRequest, ComparisonResponse

logger = logging.getLogger("ghostflow.cloud.comparisons")

cloud_comparisons_router = APIRouter(prefix="/api/cloud", tags=["cloud-comparisons"])


def _scan_to_report(scan: Scan, db: Session) -> ScanReport:
    """Reconstruct a ScanReport model from persisted database records for comparison."""
    findings_rows = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    model_findings: list[ModelFinding] = []

    for f in findings_rows:
        evidence_list = [
            Evidence(
                role=e.get("role", "frontend"),
                file=e.get("file", ""),
                line=int(e.get("line", 1)),
                source=e.get("source", ""),
            )
            for e in (f.evidence_json or [])
            if isinstance(e, dict)
        ]
        model_findings.append(
            ModelFinding(
                id=f.finding_uid,
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity,
                confidence=f.confidence,
                message=f.message,
                recommendation=f.recommendation,
                evidence=evidence_list,
                details=f.details_json or {},
                node_ids=f.node_ids_json or [],
                edge_ids=f.edge_ids_json or [],
            )
        )

    return ScanReport(
        project_path=scan.project_path,
        frontend_calls=scan.frontend_calls,
        backend_routes=scan.backend_routes,
        findings=model_findings,
        scan_id=scan.scan_id,
        timestamp=scan.created_at.isoformat() if scan.created_at else None,
        scan_mode="static_only",
    )


@cloud_comparisons_router.post("/comparisons", response_model=ComparisonResponse, status_code=status.HTTP_201_CREATED)
def create_scan_comparison(
    request: ComparisonCreateRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> ComparisonResponse:
    """Compare two historical scans within the same project and persist comparison result."""
    base_scan = _find_scan(request.base_scan_id, user.id, db)
    target_scan = _find_scan(request.target_scan_id, user.id, db)

    # Cross-project comparison is strictly prohibited
    if base_scan.project_id != target_scan.project_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot compare scans from different projects. Both scans must belong to the same project.",
        )

    base_report = _scan_to_report(base_scan, db)
    target_report = _scan_to_report(target_scan, db)

    comparison_result = compare_reports(
        older_report=base_report,
        newer_report=target_report,
        older_scan_id=base_scan.scan_id,
        newer_scan_id=target_scan.scan_id,
        older_timestamp=base_scan.created_at.isoformat() if base_scan.created_at else "",
        newer_timestamp=target_scan.created_at.isoformat() if target_scan.created_at else "",
    )

    comparison_dict = comparison_result.model_dump()
    comp_uuid = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    comparison_row = ScanComparison(
        id=comp_uuid,
        user_id=user.id,
        project_id=base_scan.project_id,
        base_scan_id=base_scan.id,
        target_scan_id=target_scan.id,
        new_findings_count=comparison_result.new_count,
        resolved_findings_count=comparison_result.resolved_count,
        unresolved_findings_count=comparison_result.still_existing_count,
        comparison_data_json=comparison_dict,
        created_at=now_utc,
    )
    db.add(comparison_row)
    db.flush()

    return ComparisonResponse(
        id=str(comparison_row.id),
        user_id=str(user.id),
        project_id=str(base_scan.project_id),
        base_scan_id=str(base_scan.id),
        target_scan_id=str(target_scan.id),
        new_findings_count=comparison_result.new_count,
        resolved_findings_count=comparison_result.resolved_count,
        unresolved_findings_count=comparison_result.still_existing_count,
        comparison_data=comparison_dict,
        created_at=now_utc.isoformat(),
    )


@cloud_comparisons_router.get("/comparisons/{comparison_id}", response_model=ComparisonResponse)
def get_comparison(
    comparison_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> ComparisonResponse:
    """Retrieve an existing comparison result."""
    try:
        comp_uuid = uuid.UUID(str(comparison_id))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Comparison record not found.")

    comp = db.query(ScanComparison).filter(ScanComparison.id == comp_uuid, ScanComparison.user_id == user.id).first()
    if not comp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Comparison record not found.")

    return ComparisonResponse(
        id=str(comp.id),
        user_id=str(comp.user_id),
        project_id=str(comp.project_id),
        base_scan_id=str(comp.base_scan_id),
        target_scan_id=str(comp.target_scan_id),
        new_findings_count=comp.new_findings_count,
        resolved_findings_count=comp.resolved_findings_count,
        unresolved_findings_count=comp.unresolved_findings_count,
        comparison_data=comp.comparison_data_json or {},
        created_at=comp.created_at.isoformat() if comp.created_at else "",
    )


@cloud_comparisons_router.get("/projects/{project_id}/comparisons", response_model=list[ComparisonResponse])
def list_project_comparisons(
    project_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> list[ComparisonResponse]:
    """List recent comparison records for a specific project."""
    try:
        proj_uuid = uuid.UUID(str(project_id))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")

    project = db.query(Project).filter(Project.id == proj_uuid, Project.user_id == user.id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")

    comparisons = (
        db.query(ScanComparison)
        .filter(ScanComparison.project_id == project.id, ScanComparison.user_id == user.id)
        .order_by(ScanComparison.created_at.desc())
        .limit(limit)
        .all()
    )

    return [
        ComparisonResponse(
            id=str(c.id),
            user_id=str(c.user_id),
            project_id=str(c.project_id),
            base_scan_id=str(c.base_scan_id),
            target_scan_id=str(c.target_scan_id),
            new_findings_count=c.new_findings_count,
            resolved_findings_count=c.resolved_findings_count,
            unresolved_findings_count=c.unresolved_findings_count,
            comparison_data=c.comparison_data_json or {},
            created_at=c.created_at.isoformat() if c.created_at else "",
        )
        for c in comparisons
    ]

