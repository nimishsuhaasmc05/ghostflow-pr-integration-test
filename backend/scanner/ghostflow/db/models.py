"""GhostFlow PostgreSQL Persistence Layer - SQLAlchemy ORM Models.

Defines cloud-first persistence models for:
- profiles (linked to Supabase Auth UUIDs)
- user_preferences
- projects
- scans
- findings
- root_causes
- scan_graphs
- scan_comparisons

All models use UUID primary keys and maintain strict foreign-key integrity.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    and_,
    func,
)
from sqlalchemy.orm import relationship

from .base import Base


class Profile(Base):
    """User profile linked 1:1 with Supabase Auth user UUID."""

    __tablename__ = "profiles"

    id = Column(
        Uuid(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    email = Column(String(255), nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    avatar_url = Column(String(1024), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    preferences = relationship(
        "UserPreference",
        back_populates="profile",
        uselist=False,
        cascade="all, delete-orphan",
    )
    projects = relationship(
        "Project",
        back_populates="profile",
        cascade="all, delete-orphan",
    )
    scans = relationship(
        "Scan",
        back_populates="profile",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Profile {self.id} email={self.email}>"


class UserPreference(Base):
    """User settings and UI preferences."""

    __tablename__ = "user_preferences"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        Uuid(as_uuid=True),
        ForeignKey("profiles.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    theme = Column(String(32), nullable=False, default="system", server_default="system")
    default_scan_mode = Column(
        String(32),
        nullable=False,
        default="deep",
        server_default="deep",
    )
    enable_ai_advisory = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    auto_detect_openapi = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    profile = relationship("Profile", back_populates="preferences")

    def __repr__(self) -> str:
        return f"<UserPreference user_id={self.user_id} theme={self.theme}>"


class Project(Base):
    """Target software project registered by a user."""

    __tablename__ = "projects"

    __table_args__ = (
        UniqueConstraint("id", "user_id", name="uq_projects_id_user_id"),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        Uuid(as_uuid=True),
        ForeignKey("profiles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    repository_url = Column(String(1024), nullable=True)
    project_type = Column(
        String(64),
        nullable=False,
        default="fullstack",
        server_default="fullstack",
    )
    is_remote = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    default_openapi_path = Column(String(512), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    profile = relationship("Profile", back_populates="projects")
    scans = relationship(
        "Scan",
        back_populates="project",
        cascade="all, delete-orphan",
        order_by="desc(Scan.created_at)",
        foreign_keys="[Scan.project_id, Scan.user_id]",
        primaryjoin="and_(Project.id == Scan.project_id, Project.user_id == Scan.user_id)",
        overlaps="scans,project",
    )

    def __repr__(self) -> str:
        return f"<Project {self.id} name={self.name}>"


class Scan(Base):
    """Execution run record of a project analysis."""

    __tablename__ = "scans"

    __table_args__ = (
        Index("idx_scans_project_created", "project_id", "created_at"),
        Index("idx_scans_user_created", "user_id", "created_at"),
        UniqueConstraint("id", "project_id", "user_id", name="uq_scans_id_project_user"),
        ForeignKeyConstraint(
            ["project_id", "user_id"],
            ["projects.id", "projects.user_id"],
            name="fk_scans_project_user",
            ondelete="CASCADE",
        ),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(String(64), nullable=False, unique=True, index=True)
    project_id = Column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )
    user_id = Column(
        Uuid(as_uuid=True),
        ForeignKey("profiles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_mode = Column(
        String(32),
        nullable=False,
        default="standard",
        server_default="standard",
    )
    status = Column(
        String(32),
        nullable=False,
        default="completed",
        server_default="completed",
    )
    scanner_version = Column(String(32), nullable=True)
    project_path = Column(String(1024), nullable=False)
    commit_hash = Column(String(64), nullable=True)
    branch = Column(String(255), nullable=True)

    # Metrics
    frontend_calls = Column(Integer, nullable=False, default=0, server_default="0")
    backend_routes = Column(Integer, nullable=False, default=0, server_default="0")
    findings_count = Column(Integer, nullable=False, default=0, server_default="0")
    high_count = Column(Integer, nullable=False, default=0, server_default="0")
    medium_count = Column(Integer, nullable=False, default=0, server_default="0")
    low_count = Column(Integer, nullable=False, default=0, server_default="0")

    duration_ms = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    project = relationship(
        "Project",
        back_populates="scans",
        foreign_keys="[Scan.project_id, Scan.user_id]",
        primaryjoin="and_(Scan.project_id == Project.id, Scan.user_id == Project.user_id)",
        overlaps="scans,project",
    )
    profile = relationship("Profile", back_populates="scans", overlaps="project,scans")
    findings = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    root_causes = relationship(
        "RootCause",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    graph = relationship(
        "ScanGraph",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Scan {self.scan_id} findings={self.findings_count}>"


class Finding(Base):
    """Individual diagnostic finding emitted by the analysis engine."""

    __tablename__ = "findings"

    __table_args__ = (
        Index("idx_findings_scan_rule", "scan_id", "rule_id"),
        Index("idx_findings_scan_severity", "scan_id", "severity"),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_uid = Column(String(64), nullable=False, index=True)
    scan_id = Column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_id = Column(String(32), nullable=False, index=True)
    category = Column(String(64), nullable=False, index=True)
    severity = Column(String(16), nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=0.80)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)

    # Structured metadata (evidence snippets, details, graph linkages)
    evidence_json = Column(JSON, nullable=False, default=list)
    details_json = Column(JSON, nullable=False, default=dict)
    node_ids_json = Column(JSON, nullable=False, default=list)
    edge_ids_json = Column(JSON, nullable=False, default=list)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    scan = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding {self.finding_uid} rule={self.rule_id} severity={self.severity}>"


class RootCause(Base):
    """Synthesized root-cause hypothesis explaining multiple downstream findings."""

    __tablename__ = "root_causes"

    __table_args__ = (
        Index("idx_root_causes_scan_severity", "scan_id", "severity"),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    candidate_id = Column(String(64), nullable=False, index=True)
    scan_id = Column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False)
    state = Column(String(32), nullable=False, default="LIKELY", server_default="LIKELY")
    confidence = Column(Float, nullable=False, default=0.80)
    severity = Column(String(16), nullable=False, default="medium", server_default="medium")
    description = Column(Text, nullable=False)
    recommended_action = Column(Text, nullable=False)
    suggested_order = Column(Integer, nullable=False, default=1, server_default="1")
    impact_summary = Column(Text, nullable=True)
    shared_entity = Column(String(255), nullable=True)

    # Structured references
    finding_ids_json = Column(JSON, nullable=False, default=list)
    affected_components_json = Column(JSON, nullable=False, default=list)
    evidence_json = Column(JSON, nullable=False, default=list)
    node_ids_json = Column(JSON, nullable=False, default=list)
    edge_ids_json = Column(JSON, nullable=False, default=list)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    scan = relationship("Scan", back_populates="root_causes")

    def __repr__(self) -> str:
        return f"<RootCause {self.candidate_id} title={self.title[:30]}>"


class ScanGraph(Base):
    """Visual dependency graph nodes and edges for an executed scan."""

    __tablename__ = "scan_graphs"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    node_count = Column(Integer, nullable=False, default=0, server_default="0")
    edge_count = Column(Integer, nullable=False, default=0, server_default="0")

    nodes_json = Column(JSON, nullable=False, default=list)
    edges_json = Column(JSON, nullable=False, default=list)
    metadata_json = Column(JSON, nullable=False, default=dict)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    scan = relationship("Scan", back_populates="graph")

    def __repr__(self) -> str:
        return f"<ScanGraph scan_id={self.scan_id} nodes={self.node_count} edges={self.edge_count}>"


class ScanComparison(Base):
    """Comparative diff between two scans of a project."""

    __tablename__ = "scan_comparisons"

    __table_args__ = (
        Index("idx_comparisons_project_created", "project_id", "created_at"),
        ForeignKeyConstraint(
            ["base_scan_id", "project_id", "user_id"],
            ["scans.id", "scans.project_id", "scans.user_id"],
            name="fk_comparisons_base_scan_project_user",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["target_scan_id", "project_id", "user_id"],
            ["scans.id", "scans.project_id", "scans.user_id"],
            name="fk_comparisons_target_scan_project_user",
            ondelete="CASCADE",
        ),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        Uuid(as_uuid=True),
        ForeignKey("profiles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id = Column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    base_scan_id = Column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )
    target_scan_id = Column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )

    new_findings_count = Column(Integer, nullable=False, default=0, server_default="0")
    resolved_findings_count = Column(Integer, nullable=False, default=0, server_default="0")
    unresolved_findings_count = Column(Integer, nullable=False, default=0, server_default="0")
    comparison_data_json = Column(JSON, nullable=False, default=dict)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    profile = relationship("Profile")
    project = relationship("Project")
    base_scan = relationship(
        "Scan",
        foreign_keys="[ScanComparison.base_scan_id, ScanComparison.project_id, ScanComparison.user_id]",
        primaryjoin="and_(ScanComparison.base_scan_id == Scan.id, ScanComparison.project_id == Scan.project_id, ScanComparison.user_id == Scan.user_id)",
        overlaps="project,profile",
    )
    target_scan = relationship(
        "Scan",
        foreign_keys="[ScanComparison.target_scan_id, ScanComparison.project_id, ScanComparison.user_id]",
        primaryjoin="and_(ScanComparison.target_scan_id == Scan.id, ScanComparison.project_id == Scan.project_id, ScanComparison.user_id == Scan.user_id)",
        overlaps="base_scan,project,profile",
    )

    def __repr__(self) -> str:
        return f"<ScanComparison base={self.base_scan_id} target={self.target_scan_id}>"

