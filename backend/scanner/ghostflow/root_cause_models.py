"""Root-Cause Intelligence Engine data models (Phase 4).

Defines typed models for finding relationships, root-cause candidates,
and multi-hop impact tracing.
"""

from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field

from .models import Severity, Evidence

RelationshipState = Literal["CONFIRMED", "LIKELY", "POSSIBLE"]

RelationshipType = Literal[
    "shared_missing_module",
    "shared_missing_dependency",
    "shared_prefix_drift",
    "shared_endpoint_defects",
    "shared_schema_model",
    "shared_configuration_defect",
    "dependent_call_chain",
]


class FindingRelationship(BaseModel):
    """Represents a deterministic causal or correlation link between two diagnostic findings."""
    source_finding_id: str
    target_finding_id: str
    relationship_type: RelationshipType
    state: RelationshipState
    confidence: float = Field(ge=0.0, le=1.0)
    shared_entity: str
    related_files: list[str] = Field(default_factory=list)
    explanation: str


class RootCauseCandidate(BaseModel):
    """Represents a synthesized root-cause hypothesis explaining multiple downstream findings."""
    id: str
    title: str
    category: str
    state: RelationshipState
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    finding_ids: list[str] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    description: str
    recommended_action: str
    suggested_order: int
    node_ids: list[str] = Field(default_factory=list)
    edge_ids: list[str] = Field(default_factory=list)
    impact_summary: str
    shared_entity: str | None = None
