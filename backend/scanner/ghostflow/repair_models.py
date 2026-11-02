from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


class ProposalOrigin(str, enum.Enum):
    DETERMINISTIC = "deterministic"
    AI_ADVISORY = "ai_advisory"


class ProposalApprovalState(str, enum.Enum):
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"
    EXPIRED = "expired"
    STALE = "stale"


@dataclass
class PatchHunk:
    """A single contiguous hunk within a file to be modified."""
    hunk_id: str
    start_line: int
    end_line: int
    original_excerpt: str
    replacement_content: str
    excerpt_sha256: str
    explanation: str


@dataclass
class ProposalFile:
    """A target file affected by a repair proposal, containing one or more hunks."""
    rel_path: str
    original_file_sha256: str
    replacement_file_sha256: str
    hunks: list[PatchHunk] = field(default_factory=list)
    diff: str = ""
    language: str = "text"


@dataclass
class ProposalVerificationPlan:
    """Verification strategy to run post-repair before committing."""
    target_finding_ids: list[str] = field(default_factory=list)
    expected_resolved_findings: list[str] = field(default_factory=list)
    prohibited_new_findings: list[str] = field(default_factory=list)
    syntax_validation_targets: list[str] = field(default_factory=list)
    strategy: str = "Rescan project and assert target findings resolved with zero new regressions."


@dataclass
class ProposalRevisionRequest:
    """Request submitted by a developer to request revisions to an existing proposal."""
    proposal_id: str
    developer_notes: str
    requested_changes: list[str] = field(default_factory=list)


@dataclass
class TripartiteAnalysis:
    """Distinguishes strictly between confirmed facts, AI inferences, and unknown information."""
    confirmed_evidence: list[str] = field(default_factory=list)
    ai_inferences: list[str] = field(default_factory=list)
    unknown_information: list[str] = field(default_factory=list)


@dataclass
class AIAdvisoryMetadata:
    """Structured advisory details separating evidence, hypothesis, and assumptions."""
    problem_summary: str = ""
    root_cause_explanation: str = ""
    suggested_changes: list[str] = field(default_factory=list)
    risks_and_side_effects: list[str] = field(default_factory=list)
    confidence_score: float = 0.8
    confidence_explanation: str = ""
    unsupported_assumptions: list[str] = field(default_factory=list)
    analysis: TripartiteAnalysis = field(default_factory=TripartiteAnalysis)


@dataclass
class IntelligentRepairProposal:
    """A complete multi-file, evidence-driven repair proposal."""
    proposal_id: str
    canonical_project_root: str
    created_at: str
    expires_at: str
    root_cause_id: str | None = None
    target_finding_ids: list[str] = field(default_factory=list)
    affected_files: list[ProposalFile] = field(default_factory=list)
    summary: str = ""
    detailed_explanation: str = ""
    expected_result: str = ""
    risks_and_limitations: list[str] = field(default_factory=list)
    verification_plan: ProposalVerificationPlan = field(default_factory=ProposalVerificationPlan)
    proposal_origin: ProposalOrigin = ProposalOrigin.DETERMINISTIC
    can_autofix: bool = False
    approval_state: ProposalApprovalState = ProposalApprovalState.PENDING_REVIEW
    ai_advisory: AIAdvisoryMetadata | None = None


@dataclass
class ProposalVerificationResult:
    """Detailed verification verdict following proposal application."""
    proposal_id: str
    transaction_id: str
    status: str  # "verified", "partial", "failed"
    resolved_finding_ids: list[str] = field(default_factory=list)
    still_existing_finding_ids: list[str] = field(default_factory=list)
    introduced_finding_ids: list[str] = field(default_factory=list)
    unrelated_findings_count: int = 0
    message: str = ""
    verified_at: str = ""


@dataclass
class ProposalExecutionResult:
    """Outcome of applying an approved proposal via the transaction engine."""
    proposal_id: str
    transaction_id: str
    success: bool
    state: str  # "committed", "rolled_back", "failed"
    modified_files: list[str] = field(default_factory=list)
    restored_files: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    verification: ProposalVerificationResult | None = None
    error_message: str | None = None
    backup_id: str | None = None


@dataclass
class ServerProposalRecord:
    """Internal server-side representation stored on disk in .ghostflow/proposals/."""
    proposal_id: str
    canonical_project_root: str
    project_root_hash: str
    created_at: str
    expires_at: str
    proposal: IntelligentRepairProposal
    file_hashes: dict[str, str] = field(default_factory=dict)
    excerpt_hashes: dict[str, str] = field(default_factory=dict)
    state: str = ProposalApprovalState.PENDING_REVIEW.value
    record_signature: str = ""
    approved_at: str | None = None
    approved_by: str | None = None
    rejected_at: str | None = None
    rejection_reason: str | None = None
    applied_at: str | None = None
    transaction_id: str | None = None
    verification_result: dict[str, Any] | None = None
