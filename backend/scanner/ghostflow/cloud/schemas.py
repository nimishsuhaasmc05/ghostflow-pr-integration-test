"""Pydantic schemas for GhostFlow Cloud Workspace API."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class ProjectCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    repository_url: str | None = Field(default=None, max_length=1024)
    project_type: str = Field(default="fullstack", max_length=64)
    default_openapi_path: str | None = Field(default=None, max_length=512)


class ProjectUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    repository_url: str | None = Field(default=None, max_length=1024)
    project_type: str | None = Field(default=None, max_length=64)
    default_openapi_path: str | None = Field(default=None, max_length=512)


class ScanSummaryResponse(BaseModel):
    id: str
    scan_id: str
    project_id: str
    user_id: str
    scan_mode: str
    status: str
    scanner_version: str | None = None
    project_path: str
    commit_hash: str | None = None
    branch: str | None = None
    frontend_calls: int = 0
    backend_routes: int = 0
    findings_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    duration_ms: int | None = None
    error_message: str | None = None
    created_at: str
    completed_at: str | None = None


class ProjectResponse(BaseModel):
    id: str
    user_id: str
    name: str
    description: str | None = None
    repository_url: str | None = None
    project_type: str = "fullstack"
    is_remote: bool = False
    default_openapi_path: str | None = None
    created_at: str
    updated_at: str
    scans_count: int = 0
    last_scan_at: str | None = None
    recent_scans: list[ScanSummaryResponse] = []


class CloudScanRequest(BaseModel):
    repo_url: str | None = Field(default=None, max_length=1024)
    openapi_path: str | None = Field(default=None, max_length=512)
    auto_detect_openapi: bool = True
    scan_mode: str = Field(default="standard", max_length=32)
    timeout_seconds: int = Field(default=45, ge=5, le=120)


class FindingResponse(BaseModel):
    id: str
    finding_uid: str
    scan_id: str
    rule_id: str
    category: str
    severity: str
    confidence: float
    title: str
    message: str
    recommendation: str
    evidence: list[dict[str, Any]] = []
    details: dict[str, Any] = {}
    node_ids: list[str] = []
    edge_ids: list[str] = []
    created_at: str


class RootCauseResponse(BaseModel):
    id: str
    candidate_id: str
    scan_id: str
    title: str
    category: str
    state: str
    confidence: float
    severity: str
    description: str
    recommended_action: str
    suggested_order: int
    impact_summary: str | None = None
    shared_entity: str | None = None
    finding_ids: list[str] = []
    affected_components: list[str] = []
    evidence: list[dict[str, Any]] = []
    node_ids: list[str] = []
    edge_ids: list[str] = []
    created_at: str


class ScanGraphResponse(BaseModel):
    id: str
    scan_id: str
    node_count: int
    edge_count: int
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}


class ScanDetailResponse(BaseModel):
    id: str
    scan_id: str
    project_id: str
    user_id: str
    scan_mode: str
    status: str
    scanner_version: str | None = None
    project_path: str
    commit_hash: str | None = None
    branch: str | None = None
    frontend_calls: int = 0
    backend_routes: int = 0
    findings_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    duration_ms: int | None = None
    error_message: str | None = None
    created_at: str
    completed_at: str | None = None
    findings: list[FindingResponse] = []
    root_causes: list[RootCauseResponse] = []
    graph: ScanGraphResponse | None = None
    resource_limits: dict[str, Any] | None = None


class ComparisonCreateRequest(BaseModel):
    base_scan_id: str = Field(min_length=8, max_length=64)
    target_scan_id: str = Field(min_length=8, max_length=64)


class ComparisonResponse(BaseModel):
    id: str
    user_id: str
    project_id: str
    base_scan_id: str
    target_scan_id: str
    new_findings_count: int
    resolved_findings_count: int
    unresolved_findings_count: int
    comparison_data: dict[str, Any]
    created_at: str

