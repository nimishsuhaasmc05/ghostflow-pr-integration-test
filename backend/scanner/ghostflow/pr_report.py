"""GhostFlow Pull Request Markdown Report Generator.
=================================================
Formats structured PR analysis into a clean, professional GitHub-flavored Markdown
comment and GitHub Actions job summary.

Guarantees:
- Embeds unique marker tag: <!-- ghostflow-pr-report -->
- Prominently distinguishes confirmed defects from candidate change impact.
- Renders collapsible details for pre-existing baseline findings.
- Never prints secrets, tokens, or private paths.
"""

from __future__ import annotations

from typing import Any
from .pr_intelligence import PRAnalysisResult


MARKER_TAG = "<!-- ghostflow-pr-report -->"


def _format_severity_badge(sev: str) -> str:
    s = sev.lower()
    if s == "high":
        return "🔴 **HIGH**"
    elif s == "medium":
        return "🟡 **MEDIUM**"
    elif s == "low":
        return "🟢 **LOW**"
    return f"**{sev.upper()}**"


def _format_finding_entry(f: dict[str, Any], idx: int) -> str:
    rule_id = f.get("rule_id", "FINDING")
    title = f.get("title", "")
    severity = _format_severity_badge(f.get("severity", "medium"))
    msg = f.get("message", "")
    recommendation = f.get("recommendation", "")
    
    evidence_lines: list[str] = []
    for ev in f.get("evidence", []):
        file_path = ev.get("file", "")
        line_num = ev.get("line", 1)
        role = ev.get("role", "source")
        snippet = ev.get("snippet", "").strip()
        if snippet:
            evidence_lines.append(f"  - `{file_path}:{line_num}` ({role}): `{snippet}`")
        else:
            evidence_lines.append(f"  - `{file_path}:{line_num}` ({role})")

    out = [
        f"#### {idx}. [{rule_id}] {title} — {severity}",
        f"{msg}",
    ]
    if evidence_lines:
        out.append("**Evidence Locations:**")
        out.extend(evidence_lines)
    if recommendation:
        out.append(f"💡 **Recommendation:** {recommendation}")

    return "\n\n".join(out)


def generate_pr_markdown_report(result: PRAnalysisResult) -> str:
    """Format PRAnalysisResult into a comprehensive, readable GitHub Pull Request comment."""
    sections: list[str] = []

    # 1. Header with Marker Tag
    sections.append(MARKER_TAG)
    
    # Verdict pill
    if result.gate_verdict == "PASS":
        verdict_badge = "### ✅ GhostFlow Quality Gate: PASSED"
    elif result.gate_verdict == "WARN":
        verdict_badge = "### ⚠️ GhostFlow Quality Gate: WARNING"
    else:
        verdict_badge = "### ❌ GhostFlow Quality Gate: FAILED"

    header_lines = [
        verdict_badge,
        f"> **Evaluation Mode:** `{result.gate_mode.upper()}` | **Scanned Files:** {result.total_files_scanned} | **API Endpoints:** {result.backend_routes_count} routes, {result.frontend_calls_count} calls",
    ]
    if result.head_sha or result.base_sha:
        sha_info = []
        if result.base_sha:
            sha_info.append(f"Base: `{result.base_sha[:7]}` ({result.base_ref or 'base'})")
        if result.head_sha:
            sha_info.append(f"Head: `{result.head_sha[:7]}` ({result.head_ref or 'HEAD'})")
        header_lines.append(f"> {' • '.join(sha_info)}")

    sections.append("\n".join(header_lines))

    # 2. Executive Metrics Matrix
    metrics_table = [
        "| Metric | Count | Status / Notes |",
        "| :--- | :---: | :--- |",
        f"| **Newly Introduced Defects** | **{len(result.new_findings)}** | {'🔴 Action Required' if result.new_findings else '🟢 None introduced'} |",
        f"| **Resolved Defects** | **{len(result.resolved_findings)}** | {'🎉 Fixed in this PR' if result.resolved_findings else '—'} |",
        f"| **Pre-existing Baseline Issues** | **{len(result.existing_findings)}** | {'ℹ️ Unchanged from base' if result.existing_findings else '—'} |",
        f"| **Database Schema Issues** | **{len(result.database_findings)}** | {'⚠️ Model/migration drift' if result.database_findings else '🟢 Schema aligned'} |",
    ]
    if result.change_impact:
        impact_level = result.change_impact.risk_level.upper()
        metrics_table.append(f"| **Candidate Change Risk** | **{impact_level}** | {result.change_impact.risk_summary or 'Static risk assessment'} |")

    sections.append("\n".join(metrics_table))

    # 3. Gate Explanation / Blockage Note
    if result.gate_verdict == "FAIL":
        sections.append(
            f"**🚨 Pull Request Blocked:** {result.gate_explanation}\n\n"
            f"Please address the **{len(result.gate_violations)} confirmed defect(s)** detailed below before merging."
        )
    elif result.gate_verdict == "WARN":
        sections.append(f"**⚠️ Warning:** {result.gate_explanation}")
    else:
        sections.append(f"**Status:** {result.gate_explanation}")

    # 4. Newly Introduced Findings (Top Priority)
    if result.new_findings:
        new_items = ["### 🚨 New Findings Introduced in this PR\n"]
        for idx, f in enumerate(result.new_findings, 1):
            new_items.append(_format_finding_entry(f, idx))
        sections.append("\n\n---\n\n".join(new_items))
    else:
        sections.append("### 🟢 Zero New Findings Introduced\nThis Pull Request introduces no new contract mismatches or schema defects.")

    # 5. Database Schema Diagnostics (DB001 - DB007)
    if result.database_findings:
        db_items = [
            "### 🗄️ Database Schema Diagnostics (SQLAlchemy & Alembic)",
            "> Pure static inspection of models and migration revisions without executing untrusted project code.\n"
        ]
        for idx, f in enumerate(result.database_findings, 1):
            db_items.append(_format_finding_entry(f, idx))
        sections.append("\n\n".join(db_items))

    # 6. Change Impact & Potential Risk (Clearly Distinguished)
    if result.change_impact and (result.change_impact.changed_files or result.change_impact.broken_contract_risks):
        impact = result.change_impact
        ci_sections = [
            "### 🔄 Git-Aware Change Impact Analysis",
            "> [!NOTE]\n"
            "> **Candidate Impact vs. Confirmed Defect Guarantee:**\n"
            "> Potential change impact maps propagation pathways statically based on Git diffs. "
            "> Candidate risks indicate recommended testing areas and **never block the quality gate** by themselves.\n"
        ]

        if impact.changed_files:
            ci_sections.append(f"**Changed Files ({len(impact.changed_files)}):**")
            files_by_role: dict[str, list[str]] = {}
            for cf in impact.changed_files:
                files_by_role.setdefault(cf.role, []).append(f"`{cf.path}` ({cf.status})")
            for role, flist in sorted(files_by_role.items()):
                ci_sections.append(f"- **{role.capitalize()}**: {', '.join(flist)}")

        if impact.affected_routes or impact.affected_calls:
            ci_sections.append(
                f"**Endpoint Correlation:** {len(impact.affected_routes)} backend route(s) and {len(impact.affected_calls)} frontend call(s) directly touched or downstream."
            )

        if impact.broken_contract_risks:
            ci_sections.append("**Candidate Propagation Risks:**")
            for cr in impact.broken_contract_risks:
                ci_sections.append(f"- **[{cr.risk_level.upper()}] {cr.title}**: {cr.potential_impact}")

        if impact.suggested_tests:
            ci_sections.append("**Suggested Verification Test Suites:**")
            for st in impact.suggested_tests:
                ci_sections.append(f"- `{st}`")

        sections.append("\n\n".join(ci_sections))

    # 7. Resolved Findings (Celebration)
    if result.resolved_findings:
        res_items = [
            f"### 🎉 Resolved Findings ({len(result.resolved_findings)})",
            "The following pre-existing defects were resolved by changes in this Pull Request:\n"
        ]
        for idx, f in enumerate(result.resolved_findings, 1):
            res_items.append(f"- **[{f.get('rule_id')}]** {f.get('title')} (`{_extract_finding_file(f)}`)")
        sections.append("\n".join(res_items))

    # 8. Root-Cause Analysis Groupings
    if result.root_causes:
        rc_items = [
            "### 🧩 Root-Cause Insights",
            "GhostFlow identified cascading symptoms linked to underlying root causes:\n"
        ]
        for rc in result.root_causes[:5]:  # show top 5 root causes
            title = rc.get("title", rc.get("id", "Root Cause"))
            rule_id = rc.get("rule_id", "")
            symptoms = rc.get("symptoms", [])
            rc_items.append(f"- **[{rule_id}] {title}**: explains {len(symptoms)} downstream symptom(s)")
        sections.append("\n".join(rc_items))

    # 9. Collapsible Pre-existing Baseline Findings (to avoid clutter)
    if result.existing_findings:
        exist_items = [
            f"<details><summary><b>Pre-existing Baseline Findings ({len(result.existing_findings)}) — Click to expand</b></summary>\n",
            "> These issues were already present in the base branch and were not introduced by this PR:\n"
        ]
        for idx, f in enumerate(result.existing_findings, 1):
            exist_items.append(f"{idx}. **[{f.get('rule_id')}]** ({f.get('severity')}) {f.get('title')} — `{_extract_finding_file(f)}`")
        exist_items.append("\n</details>")
        sections.append("\n".join(exist_items))

    # 10. Unverified Areas (if any)
    if result.unverified_areas:
        unv_items = [
            "### ⚠️ Unverified Analysis Areas",
            "> The following aspects could not be completely confirmed statically:\n"
        ]
        for unv in result.unverified_areas:
            unv_items.append(f"- {unv}")
        sections.append("\n".join(unv_items))

    # 11. Footer
    sections.append(
        "\n---\n"
        "<sub>GhostFlow v0.4.0 • Independent Static API Contract & Database Intelligence • Local-First • Zero Cloud AI Transmission</sub>"
    )

    return "\n\n".join(sections)


def _extract_finding_file(f: dict[str, Any]) -> str:
    evs = f.get("evidence", [])
    if evs and isinstance(evs, list) and len(evs) > 0:
        first = evs[0]
        if isinstance(first, dict):
            return f"{first.get('file', '')}:{first.get('line', 1)}"
    return "N/A"

