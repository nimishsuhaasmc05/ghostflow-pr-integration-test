from __future__ import annotations

import hashlib
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analyzer import scan_project
from .models import Finding, Evidence
from .proposal_store import (
    ServerProposalStore,
    ProposalAlreadyAppliedError,
    ProposalExpiredError,
    ProposalNotFoundError,
    ProposalStaleError,
    ProposalStoreError,
    ProposalTamperedError,
)
from .repair import SAFE_AUTOFIX_RULES, validate_safe_path
from .repair_models import (
    IntelligentRepairProposal,
    PatchHunk,
    ProposalApprovalState,
    ProposalExecutionResult,
    ProposalFile,
    ProposalOrigin,
    ProposalVerificationResult,
)
from .syntax_validator import validate_file_syntax
from .transaction import (
    FileRepairTarget,
    RepairTransactionManager,
    TransactionError,
    TransactionResult,
    TransactionState,
)


class ProposalExecutionError(Exception):
    """Raised when an approved proposal cannot be applied."""
    pass


def _extract_findings(scan_result: Any) -> list[Finding]:
    """Extract Finding objects safely whether scan_result is a dataclass, pydantic model, or dict."""
    raw = scan_result.findings if hasattr(scan_result, "findings") else scan_result.get("findings", [])
    out: list[Finding] = []
    for item in raw:
        if isinstance(item, Finding):
            out.append(item)
        elif isinstance(item, dict):
            evs = [Evidence(**e) if isinstance(e, dict) else e for e in item.get("evidence", [])]
            copy_dict = dict(item)
            copy_dict["evidence"] = evs
            out.append(Finding(**copy_dict))
    return out


def apply_approved_proposal(
    project_root: Path,
    proposal_id: str,
    allowed_roots: list[Path] | None = None,
) -> ProposalExecutionResult:
    """Apply an approved multi-file repair proposal via the transactional repair engine.

    Validates cryptographic signature, approval state, and fresh disk file hashes.
    Executes all changes in one coordinated transaction with byte-for-byte rollback protection.
    Runs automated post-apply verification scan to confirm findings resolution.
    """
    canonical_root = project_root.expanduser().resolve()

    # 1. Retrieve validated server record (checks signature, project binding, expiration, stale drift)
    record = ServerProposalStore.get_proposal_record(
        canonical_root,
        proposal_id,
        validate_disk_hashes=True,
        allowed_roots=allowed_roots,
    )
    proposal = record.proposal

    # 2. Enforce explicit approval state
    if record.state != ProposalApprovalState.APPROVED.value:
        raise ProposalExecutionError(
            f"Cannot apply proposal '{proposal_id}': proposal is in '{record.state}' state. "
            "Proposals must be explicitly approved by developer before application."
        )

    # 3. Rule whitelist verification
    # For deterministic proposals, rule safety was checked during proposal generation.
    # For AI advisory proposals entering execution, enforce that target findings belong to SAFE_AUTOFIX_RULES.
    if proposal.proposal_origin == ProposalOrigin.AI_ADVISORY:
        # Re-scan to verify current finding rules
        current_scan = scan_project(canonical_root, allowed_roots=allowed_roots)
        current_findings = {f.id: f for f in _extract_findings(current_scan)}
        for fid in proposal.target_finding_ids:
            if fid in current_findings:
                f_obj = current_findings[fid]
                if f_obj.rule_id not in SAFE_AUTOFIX_RULES:
                    raise ProposalExecutionError(
                        f"AI proposal targets finding '{fid}' with rule '{f_obj.rule_id}' "
                        f"which is outside SAFE_AUTOFIX_RULES {sorted(SAFE_AUTOFIX_RULES)}. "
                        "Automatic transaction modification is prohibited."
                    )

    if not proposal.affected_files:
        raise ProposalExecutionError(
            f"Proposal '{proposal_id}' contains no file modifications to apply."
        )

    # 4. Assemble and revalidate FileRepairTargets
    file_targets: list[FileRepairTarget] = []
    initial_scan = scan_project(canonical_root, allowed_roots=allowed_roots)
    initial_finding_ids = {f.id for f in _extract_findings(initial_scan)}

    for pf in proposal.affected_files:
        abs_path = validate_safe_path(pf.rel_path, canonical_root, allowed_roots)
        if not abs_path.is_file():
            raise ProposalExecutionError(f"Target file '{pf.rel_path}' does not exist on disk.")

        curr_bytes = abs_path.read_bytes()
        curr_sha = hashlib.sha256(curr_bytes).hexdigest()
        if curr_sha != pf.original_file_sha256:
            raise ProposalStaleError(
                f"File '{pf.rel_path}' content has changed since proposal review. Application aborted."
            )

        orig_text = curr_bytes.decode("utf-8", errors="replace")
        orig_lines = orig_text.splitlines(keepends=True)

        # Apply hunks bottom-to-top to preserve line numbers
        sorted_hunks = sorted(pf.hunks, key=lambda h: h.start_line)
        modified_lines = list(orig_lines)
        for h in reversed(sorted_hunks):
            h_start = h.start_line - 1
            h_end = h.end_line
            rep_lines = h.replacement_content.splitlines(keepends=True)
            modified_lines[h_start:h_end] = rep_lines

        modified_text = "".join(modified_lines)
        mod_sha = hashlib.sha256(modified_text.encode("utf-8")).hexdigest()

        # Syntax validation
        syntax_res = validate_file_syntax(abs_path, modified_text, canonical_root)
        if not syntax_res.valid:
            raise ProposalExecutionError(
                f"Proposed modification to '{pf.rel_path}' failed syntax validation: {syntax_res.error_message}"
            )

        file_targets.append(
            FileRepairTarget(
                rel_path=pf.rel_path,
                expected_file_hash=pf.original_file_sha256,
                replacement_bytes=modified_text.encode("utf-8"),
            )
        )

    # 5. Execute coordinated multi-file transaction
    tx_result = RepairTransactionManager.execute_transaction(
        canonical_root,
        targets=file_targets,
        proposal_id=proposal_id,
        allowed_roots=allowed_roots,
    )

    if not tx_result.success:
        return ProposalExecutionResult(
            proposal_id=proposal_id,
            transaction_id=tx_result.transaction_id,
            success=False,
            state=tx_result.state.value,
            modified_files=tx_result.modified_files,
            restored_files=tx_result.restored_files,
            conflicts=tx_result.conflicts,
            error_message=tx_result.error_message,
            backup_id=tx_result.transaction_id,
        )

    # 6. Post-Application Verification Scan
    fresh_scan = scan_project(canonical_root, allowed_roots=allowed_roots)
    fresh_finding_ids = {f.id for f in _extract_findings(fresh_scan)}

    resolved = [fid for fid in proposal.target_finding_ids if fid not in fresh_finding_ids]
    still_existing = [fid for fid in proposal.target_finding_ids if fid in fresh_finding_ids]
    introduced = [fid for fid in fresh_finding_ids if fid not in initial_finding_ids and fid not in proposal.target_finding_ids]
    unrelated_count = len(fresh_finding_ids - set(proposal.target_finding_ids) - set(introduced))

    if introduced:
        verdict = "failed"
        verdict_msg = f"Verification failed: {len(introduced)} new regression finding(s) introduced ({', '.join(introduced)})."
    elif not resolved:
        verdict = "failed"
        verdict_msg = "Verification failed: target findings were not resolved by the applied patch."
    elif still_existing:
        verdict = "partial"
        verdict_msg = f"Partially verified: {len(resolved)} resolved, {len(still_existing)} still existing ({', '.join(still_existing)})."
    else:
        verdict = "verified"
        verdict_msg = f"Successfully verified: all {len(resolved)} target finding(s) resolved with zero regressions."

    v_report = ProposalVerificationResult(
        proposal_id=proposal_id,
        transaction_id=tx_result.transaction_id,
        status=verdict,
        resolved_finding_ids=resolved,
        still_existing_finding_ids=still_existing,
        introduced_finding_ids=introduced,
        unrelated_findings_count=unrelated_count,
        message=verdict_msg,
        verified_at=datetime.now(timezone.utc).isoformat(),
    )

    # 7. Mark proposal APPLIED and record verification result
    ServerProposalStore.mark_applied(
        canonical_root,
        proposal_id,
        transaction_id=tx_result.transaction_id,
        verification_result=asdict(v_report),
    )

    return ProposalExecutionResult(
        proposal_id=proposal_id,
        transaction_id=tx_result.transaction_id,
        success=True,
        state=tx_result.state.value,
        modified_files=tx_result.modified_files,
        verification=v_report,
        backup_id=tx_result.transaction_id,
    )


def rollback_proposal_transaction(
    project_root: Path,
    transaction_id: str,
    allowed_roots: list[Path] | None = None,
) -> ProposalExecutionResult:
    """Roll back a committed transaction and perform fresh verification."""
    canonical_root = project_root.expanduser().resolve()

    tx_res = RepairTransactionManager.rollback_transaction(
        canonical_root,
        transaction_id=transaction_id,
        allowed_roots=allowed_roots,
    )

    # Run verification scan post-rollback
    post_scan = scan_project(canonical_root, allowed_roots=allowed_roots)

    return ProposalExecutionResult(
        proposal_id=transaction_id,
        transaction_id=transaction_id,
        success=tx_res.success,
        state=tx_res.state.value,
        modified_files=[],
        restored_files=tx_res.restored_files,
        conflicts=tx_res.conflicts,
        error_message=tx_res.error_message,
        backup_id=transaction_id,
    )
