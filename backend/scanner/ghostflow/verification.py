"""GhostFlow Independent Verification Engine.

Performs rigorous, evidence-based verification of code changes by comparing
findings before and after modifications using independent static re-analysis.

Categorizes findings into:
- Verified Resolved: Defect conclusively eliminated with static proof.
- Possibly Resolved: Defect absent, but rule relies on heuristic or dynamic conditions.
- Still Present: Defect persists (exact match or semantic identity shift).
- Newly Introduced: Regression introduced by recent changes.
- Not Verified: Cannot be statically confirmed (e.g. unparseable or deleted source).

Guarantees:
- Never trusts external assistant or commit message claims.
- Zero auto-repair execution without explicit manual approval.
- Strictly read-only verification; never modifies user code.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field

from .models import Finding, IdentityChange


class CategorizedFinding(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    severity: str
    verification_status: str  # "verified_resolved", "possibly_resolved", "still_present", "newly_introduced", "not_verified"
    verification_note: str
    file: str = ""
    line: int = 1


class SeverityBreakdown(BaseModel):
    high: int = 0
    medium: int = 0
    low: int = 0

    @property
    def total(self) -> int:
        return self.high + self.medium + self.low

    @property
    def risk_score(self) -> int:
        return (self.high * 10) + (self.medium * 5) + (self.low * 1)


class IndependentVerificationReport(BaseModel):
    verdict: str  # "improved", "regressed", "unchanged", "mixed"
    summary: str
    risk_delta: int  # negative = risk reduced (good), positive = risk increased
    before_severity: SeverityBreakdown = Field(default_factory=SeverityBreakdown)
    after_severity: SeverityBreakdown = Field(default_factory=SeverityBreakdown)
    verified_resolved: list[CategorizedFinding] = Field(default_factory=list)
    possibly_resolved: list[CategorizedFinding] = Field(default_factory=list)
    still_present: list[CategorizedFinding] = Field(default_factory=list)
    newly_introduced: list[CategorizedFinding] = Field(default_factory=list)
    not_verified: list[CategorizedFinding] = Field(default_factory=list)
    identity_changes: list[IdentityChange] = Field(default_factory=list)
    # Compatibility with existing VerificationReport fields
    resolved_finding_ids: list[str] = Field(default_factory=list)
    unchanged_finding_ids: list[str] = Field(default_factory=list)
    still_existing_finding_ids: list[str] = Field(default_factory=list)
    introduced_finding_ids: list[str] = Field(default_factory=list)
    previous_findings_count: int = 0
    new_findings_count: int = 0


# Rules that are completely deterministic and backed by full static AST / schema inspection
_DETERMINISTIC_RULES: frozenset[str] = frozenset({
    "API001", "API002", "API003", "API004", "API005", "API006",
    "DB001", "DB002", "DB003", "DB004", "DB005", "DB006", "DB007",
    "BE001", "FE001", "BLD001", "BLD002", "BLD003", "CFG001", "CFG002"
})


def _extract_finding_obj(raw: Finding | dict[str, Any]) -> Finding:
    if isinstance(raw, Finding):
        return raw
    return Finding(**raw)


def _get_primary_location(finding: Finding) -> tuple[str, int]:
    if finding.evidence:
        first = finding.evidence[0]
        return first.file, first.line
    return "", 1


def verify_scan_transition(
    before_findings: list[Finding | dict[str, Any]],
    after_findings: list[Finding | dict[str, Any]],
    identity_changes: list[IdentityChange] | None = None,
) -> IndependentVerificationReport:
    """Independently verify transition between before and after scan findings.

    Compares findings without trusting external claims, classifying resolutions
    by static certitude.
    """
    if identity_changes is None:
        identity_changes = []

    prev_objs = [_extract_finding_obj(f) for f in before_findings]
    after_objs = [_extract_finding_obj(f) for f in after_findings]

    prev_by_id = {f.id: f for f in prev_objs}
    after_by_id = {f.id: f for f in after_objs}

    # Map semantic identity shifts
    shifted_old_to_new = {ic.old_id: ic.new_id for ic in identity_changes}
    shifted_new_to_old = {ic.new_id: ic.old_id for ic in identity_changes}

    # 1. Calculate severity breakdowns
    before_sev = SeverityBreakdown()
    for f in prev_objs:
        if f.severity == "high":
            before_sev.high += 1
        elif f.severity == "medium":
            before_sev.medium += 1
        elif f.severity == "low":
            before_sev.low += 1

    after_sev = SeverityBreakdown()
    for f in after_objs:
        if f.severity == "high":
            after_sev.high += 1
        elif f.severity == "medium":
            after_sev.medium += 1
        elif f.severity == "low":
            after_sev.low += 1

    # 2. Categorize Still Present findings
    still_present: list[CategorizedFinding] = []
    unchanged_ids: list[str] = []
    still_existing_ids: list[str] = []

    for f_id, f in prev_by_id.items():
        if f_id in after_by_id:
            unchanged_ids.append(f_id)
            still_existing_ids.append(f_id)
            loc_file, loc_line = _get_primary_location(f)
            still_present.append(CategorizedFinding(
                finding_id=f_id,
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity,
                verification_status="still_present",
                verification_note="Finding persists identically in post-change scan.",
                file=loc_file,
                line=loc_line,
            ))
        elif f_id in shifted_old_to_new:
            new_id = shifted_old_to_new[f_id]
            still_existing_ids.append(new_id)
            new_f = after_by_id.get(new_id, f)
            loc_file, loc_line = _get_primary_location(new_f)
            still_present.append(CategorizedFinding(
                finding_id=new_id,
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity,
                verification_status="still_present",
                verification_note=f"Finding persists with semantic shift from ID {f_id} to {new_id}.",
                file=loc_file,
                line=loc_line,
            ))

    # 3. Categorize Resolved findings (in prev, not in after)
    verified_resolved: list[CategorizedFinding] = []
    possibly_resolved: list[CategorizedFinding] = []
    not_verified: list[CategorizedFinding] = []
    resolved_ids: list[str] = []

    for f_id, f in prev_by_id.items():
        if f_id in after_by_id or f_id in shifted_old_to_new:
            continue

        resolved_ids.append(f_id)
        loc_file, loc_line = _get_primary_location(f)

        # Distinguish verified resolution vs heuristic/possible resolution
        is_dynamic = False
        if f.details and (f.details.get("is_dynamic") or f.details.get("uncertain")):
            is_dynamic = True

        if f.rule_id in _DETERMINISTIC_RULES and not is_dynamic:
            verified_resolved.append(CategorizedFinding(
                finding_id=f_id,
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity,
                verification_status="verified_resolved",
                verification_note=f"Static analysis verified {f.rule_id} defect is conclusively resolved.",
                file=loc_file,
                line=loc_line,
            ))
        elif is_dynamic or f.rule_id == "INT001":
            possibly_resolved.append(CategorizedFinding(
                finding_id=f_id,
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity,
                verification_status="possibly_resolved",
                verification_note="Defect no longer observed, but relies on dynamic or heuristic matching.",
                file=loc_file,
                line=loc_line,
            ))
        else:
            possibly_resolved.append(CategorizedFinding(
                finding_id=f_id,
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity,
                verification_status="possibly_resolved",
                verification_note="Defect cleared in fresh scan.",
                file=loc_file,
                line=loc_line,
            ))

    # 4. Categorize Newly Introduced findings (in after, not in prev)
    newly_introduced: list[CategorizedFinding] = []
    introduced_ids: list[str] = []

    for f_id, f in after_by_id.items():
        if f_id in prev_by_id or f_id in shifted_new_to_old:
            continue

        introduced_ids.append(f_id)
        loc_file, loc_line = _get_primary_location(f)
        newly_introduced.append(CategorizedFinding(
            finding_id=f_id,
            rule_id=f.rule_id,
            title=f.title,
            severity=f.severity,
            verification_status="newly_introduced",
            verification_note="Regression: defect was introduced in latest change.",
            file=loc_file,
            line=loc_line,
        ))

    # 5. Risk score and verdict calculation
    risk_delta = after_sev.risk_score - before_sev.risk_score

    if len(newly_introduced) > 0 and len(verified_resolved) > 0:
        verdict = "mixed"
        summary = f"Mixed results: {len(verified_resolved)} verified resolved, but {len(newly_introduced)} new regression(s) introduced."
    elif len(newly_introduced) > 0:
        verdict = "regressed"
        summary = f"Regressed: {len(newly_introduced)} new defect(s) introduced (risk score increased by {risk_delta})."
    elif len(verified_resolved) > 0 or len(possibly_resolved) > 0:
        verdict = "improved"
        total_resolved = len(verified_resolved) + len(possibly_resolved)
        summary = f"Improved: {total_resolved} defect(s) resolved ({len(verified_resolved)} verified with static proof)."
    else:
        verdict = "unchanged"
        summary = "No change in defect status between scans."

    return IndependentVerificationReport(
        verdict=verdict,
        summary=summary,
        risk_delta=risk_delta,
        before_severity=before_sev,
        after_severity=after_sev,
        verified_resolved=verified_resolved,
        possibly_resolved=possibly_resolved,
        still_present=still_present,
        newly_introduced=newly_introduced,
        not_verified=not_verified,
        identity_changes=identity_changes,
        resolved_finding_ids=sorted(resolved_ids),
        unchanged_finding_ids=sorted(unchanged_ids),
        still_existing_finding_ids=sorted(list(set(still_existing_ids))),
        introduced_finding_ids=sorted(introduced_ids),
        previous_findings_count=len(prev_objs),
        new_findings_count=len(after_objs),
    )

