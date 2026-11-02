"""GhostFlow Cloud Project Management API Endpoints."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..auth.dependencies import get_authenticated_db, get_current_user
from ..auth.models import AuthenticatedUser
from ..db.models import Profile, Project, Scan
from ..db.sanitizer import sanitize_repository_url
from ..remote_scanner import validate_github_url
from .schemas import (
    ProjectCreateRequest,
    ProjectResponse,
    ProjectUpdateRequest,
    ScanSummaryResponse,
)

logger = logging.getLogger("ghostflow.cloud.projects")

cloud_projects_router = APIRouter(prefix="/api/cloud/projects", tags=["cloud-projects"])


def _ensure_profile_exists(user: AuthenticatedUser, db: Session) -> Profile:
    """Ensure a profile record exists for the authenticated user to satisfy FK constraints."""
    profile = db.query(Profile).filter(Profile.id == user.id).first()
    if profile is None:
        try:
            profile = Profile(
                id=user.id,
                email=user.email or f"{user.id}@ghostflow.local",
                full_name=user.claims.get("user_metadata", {}).get("full_name"),
                avatar_url=user.claims.get("user_metadata", {}).get("avatar_url"),
            )
            db.add(profile)
            db.flush()
        except Exception as exc:
            db.rollback()
            logger.warning("Could not auto-create profile for %s: %s", user.id, exc)
            # Re-query in case it was created concurrently
            profile = db.query(Profile).filter(Profile.id == user.id).first()
            if profile is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="User profile could not be initialized.",
                ) from exc
    return profile


def _parse_uuid(val: str, entity_name: str = "Project") -> uuid.UUID:
    """Safely parse a UUID string or raise 404."""
    try:
        return uuid.UUID(str(val))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{entity_name} not found.")


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


@cloud_projects_router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(
    body: ProjectCreateRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> ProjectResponse:
    """Create a new cloud project owned by the authenticated user."""
    _ensure_profile_exists(user, db)

    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Project name cannot be empty.")

    clean_repo_url: str | None = None
    is_remote = False
    if body.repository_url:
        raw_url = body.repository_url.strip()
        if raw_url:
            if "github.com" in raw_url.lower():
                try:
                    _, _, normalized = validate_github_url(raw_url)
                    clean_repo_url = normalized
                    is_remote = True
                except ValueError as exc:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
            else:
                clean_repo_url = sanitize_repository_url(raw_url) or raw_url
                is_remote = clean_repo_url.startswith("http://") or clean_repo_url.startswith("https://")

    project = Project(
        id=uuid.uuid4(),
        user_id=user.id,
        name=name,
        description=body.description.strip() if body.description else None,
        repository_url=clean_repo_url,
        project_type=body.project_type or "fullstack",
        is_remote=is_remote,
        default_openapi_path=body.default_openapi_path.strip() if body.default_openapi_path else None,
    )
    db.add(project)
    db.flush()

    return ProjectResponse(
        id=str(project.id),
        user_id=str(project.user_id),
        name=project.name,
        description=project.description,
        repository_url=project.repository_url,
        project_type=project.project_type,
        is_remote=project.is_remote,
        default_openapi_path=project.default_openapi_path,
        created_at=project.created_at.isoformat() if project.created_at else "",
        updated_at=project.updated_at.isoformat() if project.updated_at else "",
        scans_count=0,
        last_scan_at=None,
        recent_scans=[],
    )


@cloud_projects_router.get("", response_model=list[dict[str, Any]])
def list_projects(
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> list[dict[str, Any]]:
    """List all cloud projects owned by the authenticated user with scan statistics."""
    projects = (
        db.query(Project)
        .filter(Project.user_id == user.id)
        .order_by(Project.created_at.desc())
        .all()
    )

    results: list[dict[str, Any]] = []
    for p in projects:
        # Get aggregate scan counts and latest scan date
        scan_stats = (
            db.query(func.count(Scan.id), func.max(Scan.created_at))
            .filter(Scan.project_id == p.id, Scan.user_id == user.id)
            .first()
        )
        scans_count = scan_stats[0] if scan_stats else 0
        last_scan_at = scan_stats[1].isoformat() if (scan_stats and scan_stats[1]) else None

        results.append({
            "id": str(p.id),
            "user_id": str(p.user_id),
            "name": p.name,
            "description": p.description,
            "repository_url": p.repository_url,
            "project_type": p.project_type,
            "is_remote": p.is_remote,
            "default_openapi_path": p.default_openapi_path,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None,
            "scans_count": scans_count,
            "last_scan_at": last_scan_at,
        })

    return results


@cloud_projects_router.get("/{project_id}", response_model=ProjectResponse)
def get_project_detail(
    project_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> ProjectResponse:
    """Retrieve details and recent scan history of a specific cloud project."""
    proj_uuid = _parse_uuid(project_id, "Project")
    project = db.query(Project).filter(Project.id == proj_uuid, Project.user_id == user.id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")

    scans = (
        db.query(Scan)
        .filter(Scan.project_id == project.id, Scan.user_id == user.id)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )
    total_scans = db.query(func.count(Scan.id)).filter(Scan.project_id == project.id, Scan.user_id == user.id).scalar() or 0
    recent_scans = [_scan_to_summary(s) for s in scans]
    last_scan = recent_scans[0].created_at if recent_scans else None

    return ProjectResponse(
        id=str(project.id),
        user_id=str(project.user_id),
        name=project.name,
        description=project.description,
        repository_url=project.repository_url,
        project_type=project.project_type,
        is_remote=project.is_remote,
        default_openapi_path=project.default_openapi_path,
        created_at=project.created_at.isoformat() if project.created_at else "",
        updated_at=project.updated_at.isoformat() if project.updated_at else "",
        scans_count=total_scans,
        last_scan_at=last_scan,
        recent_scans=recent_scans,
    )


@cloud_projects_router.put("/{project_id}", response_model=ProjectResponse)
@cloud_projects_router.patch("/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: str,
    body: ProjectUpdateRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> ProjectResponse:
    """Update metadata for an existing cloud project."""
    proj_uuid = _parse_uuid(project_id, "Project")
    project = db.query(Project).filter(Project.id == proj_uuid, Project.user_id == user.id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")

    if body.name is not None:
        name = body.name.strip()
        if not name:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Project name cannot be empty.")
        project.name = name

    if body.description is not None:
        project.description = body.description.strip() or None

    if body.repository_url is not None:
        raw_url = body.repository_url.strip()
        if raw_url:
            if "github.com" in raw_url.lower():
                try:
                    _, _, normalized = validate_github_url(raw_url)
                    project.repository_url = normalized
                    project.is_remote = True
                except ValueError as exc:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
            else:
                clean_repo = sanitize_repository_url(raw_url) or raw_url
                project.repository_url = clean_repo
                project.is_remote = clean_repo.startswith("http://") or clean_repo.startswith("https://")
        else:
            project.repository_url = None
            project.is_remote = False

    if body.project_type is not None:
        project.project_type = body.project_type

    if body.default_openapi_path is not None:
        project.default_openapi_path = body.default_openapi_path.strip() or None

    project.updated_at = datetime.now(timezone.utc)
    db.flush()

    total_scans = db.query(func.count(Scan.id)).filter(Scan.project_id == project.id, Scan.user_id == user.id).scalar() or 0

    return ProjectResponse(
        id=str(project.id),
        user_id=str(project.user_id),
        name=project.name,
        description=project.description,
        repository_url=project.repository_url,
        project_type=project.project_type,
        is_remote=project.is_remote,
        default_openapi_path=project.default_openapi_path,
        created_at=project.created_at.isoformat() if project.created_at else "",
        updated_at=project.updated_at.isoformat() if project.updated_at else "",
        scans_count=total_scans,
        last_scan_at=None,
        recent_scans=[],
    )


@cloud_projects_router.delete("/{project_id}")
def delete_project(
    project_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> dict[str, Any]:
    """Delete a cloud project and cascade-delete all associated scans, findings, graphs, and comparisons."""
    proj_uuid = _parse_uuid(project_id, "Project")
    project = db.query(Project).filter(Project.id == proj_uuid, Project.user_id == user.id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")

    db.delete(project)
    db.flush()

    return {"status": "deleted", "project_id": str(proj_uuid)}


@cloud_projects_router.get("/{project_id}/scans", response_model=list[ScanSummaryResponse])
def list_project_scans(
    project_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> list[ScanSummaryResponse]:
    """List historical scans for a specific cloud project."""
    proj_uuid = _parse_uuid(project_id, "Project")
    project = db.query(Project).filter(Project.id == proj_uuid, Project.user_id == user.id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")

    scans = (
        db.query(Scan)
        .filter(Scan.project_id == project.id, Scan.user_id == user.id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .all()
    )

    return [_scan_to_summary(s) for s in scans]

