from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field

Severity = Literal["high", "medium", "low"]
NodeType = Literal["frontend_call", "backend_route", "schema_model", "finding", "root_cause", "component_file"]
EdgeType = Literal[
    "calls_route",
    "uses_request_schema",
    "uses_response_schema",
    "references_model",
    "flags_issue",
    "causes_finding",
    "affects_component",
    "declared_in_file",
]


class SchemaField(BaseModel):
    name: str
    type_name: str
    is_required: bool = True
    nested_model: str | None = None
    nested_fields: dict[str, SchemaField] | None = None
    file: str | None = None
    line: int | None = None
    source: str | None = None
    alias: str | None = None


class SchemaModel(BaseModel):
    name: str
    file: str
    line: int
    source: str
    fields: dict[str, SchemaField] = Field(default_factory=dict)


class ApiCall(BaseModel):
    method: str
    path: str
    file: str
    line: int
    source: str
    request_type: str | None = None
    response_type: str | None = None
    request_schema: SchemaModel | None = None
    response_schema: SchemaModel | None = None
    path_param_types: dict[str, str] = Field(default_factory=dict)
    raw_path_params: list[str] = Field(default_factory=list)
    is_dynamic: bool = False
    has_auth_header: bool = False


class ApiRoute(BaseModel):
    method: str
    path: str
    file: str
    line: int
    source: str
    path_params: list[str] = Field(default_factory=list)
    path_param_types: dict[str, str] = Field(default_factory=dict)
    request_model: str | None = None
    response_model: str | None = None
    request_schema: SchemaModel | None = None
    response_schema: SchemaModel | None = None
    query_params: list[str] = Field(default_factory=list)
    required_query_params: list[str] = Field(default_factory=list)
    is_authenticated: bool = False


class Evidence(BaseModel):
    role: Literal["frontend", "backend", "specification"]
    file: str
    line: int
    source: str


class OpenApiSpecInfo(BaseModel):
    title: str = "OpenAPI Specification"
    version: str = "1.0.0"
    spec_version: str = "3.0.0"
    path: str
    operations_count: int = 0


class OpenApiDisagreement(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: Severity = "medium"
    confidence: float = Field(ge=0, le=1, default=0.80)
    category: str = "Specification Disagreement"
    message: str
    recommendation: str
    uncertainty_note: str = "The specification may be ahead of, behind, or intentionally broader than the implementation."
    evidence: list[Evidence] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    message: str
    recommendation: str
    evidence: list[Evidence]
    category: str | None = None
    details: dict[str, Any] | None = None
    node_ids: list[str] = Field(default_factory=list)
    edge_ids: list[str] = Field(default_factory=list)
    is_symptom: bool = False
    parent_root_cause_id: str | None = None
    suppression_reason: str | None = None


class GraphNode(BaseModel):
    id: str
    type: NodeType
    label: str
    sublabel: str | None = None
    file: str | None = None
    line: int | None = None
    source: str | None = None
    severity: Severity | None = None
    role: Literal["frontend", "backend", "shared"] = "shared"
    metadata: dict[str, Any] = Field(default_factory=dict)
    position: dict[str, float] = Field(default_factory=lambda: {"x": 0.0, "y": 0.0})


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    type: EdgeType
    label: str | None = None
    is_mismatch: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class DependencyGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class ScanReport(BaseModel):
    project_path: str
    frontend_calls: int
    backend_routes: int
    findings: list[Finding]
    graph: DependencyGraph | None = None
    scan_id: str | None = None
    timestamp: str | None = None
    root_causes: list[dict[str, Any]] = Field(default_factory=list)
    finding_relationships: list[dict[str, Any]] = Field(default_factory=list)
    monorepo_structure: dict[str, Any] | None = None


class ScanHistorySummary(BaseModel):
    scan_id: str
    timestamp: str
    project_path: str
    frontend_calls: int
    backend_routes: int
    findings_count: int
    high_count: int
    medium_count: int
    low_count: int
    schema_version: int = 1


class ScanHistoryDetail(BaseModel):
    scan_id: str
    timestamp: str
    project_path: str
    frontend_calls: int
    backend_routes: int
    findings_count: int
    high_count: int
    medium_count: int
    low_count: int
    schema_version: int = 1
    report: ScanReport


class PatchProposal(BaseModel):
    finding_id: str
    rule_id: str
    file: str
    start_line: int
    end_line: int
    original_code: str
    replacement_code: str
    explanation: str
    confidence: float
    can_autofix: bool
    validation_status: Literal["valid", "stale", "ambiguous", "unsupported"]
    content_hash: str
    diff: str
    backup_id: str | None = None


class RepairExplanation(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    mismatch_summary: str
    frontend_evidence: Evidence | None = None
    backend_evidence: Evidence | None = None
    expected_behavior: str
    actual_behavior: str
    suggested_correction: str
    why_correction_works: str
    confidence: float
    can_autofix: bool


class IdentityChange(BaseModel):
    old_id: str
    new_id: str
    rule_id: str
    reason: str
    details: dict[str, Any] = Field(default_factory=dict)


class SeverityBreakdown(BaseModel):
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanComparisonResult(BaseModel):
    older_scan_id: str
    older_timestamp: str
    older_project_path: str
    newer_scan_id: str
    newer_timestamp: str
    newer_project_path: str
    different_projects: bool
    older_findings_count: int
    newer_findings_count: int
    resolved_count: int
    still_existing_count: int
    new_count: int
    older_severity: SeverityBreakdown = Field(default_factory=SeverityBreakdown)
    newer_severity: SeverityBreakdown = Field(default_factory=SeverityBreakdown)
    resolved_findings: list[Finding] = Field(default_factory=list)
    still_existing_findings: list[Finding] = Field(default_factory=list)
    new_findings: list[Finding] = Field(default_factory=list)
    identity_changes: list[IdentityChange] = Field(default_factory=list)


class VerificationReport(BaseModel):
    resolved_finding_ids: list[str] = Field(default_factory=list)
    unchanged_finding_ids: list[str] = Field(default_factory=list)
    still_existing_finding_ids: list[str] = Field(default_factory=list)
    introduced_finding_ids: list[str] = Field(default_factory=list)
    identity_changes: list[IdentityChange] = Field(default_factory=list)
    previous_findings_count: int
    new_findings_count: int
    new_findings: list[Finding] = Field(default_factory=list)


class RepairApplyResult(BaseModel):
    status: Literal["applied", "failed", "stale"]
    message: str
    backup_id: str | None = None
    file: str
    verification: VerificationReport | None = None


class RollbackResult(BaseModel):
    status: Literal["rolled_back", "failed"]
    message: str
    file: str
    verification: VerificationReport | None = None

