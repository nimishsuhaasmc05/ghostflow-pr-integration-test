"""
GhostFlow Command-Line Interface (CLI)
=====================================
Provides headless / terminal contract scanning for CI/CD pipelines,
git pre-commit hooks, and terminal developer workflows.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from ghostflow.analyzer import scan_project


def format_text_report(report: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("  GhostFlow API Contract Analysis Report")
    lines.append("=" * 70)
    lines.append(f"Project Target:  {report.get('project_path', 'N/A')}")
    lines.append(f"Scan Mode:       {report.get('scan_mode', 'N/A')}")
    lines.append(f"Frontend Calls:  {report.get('frontend_calls', 0)}")
    lines.append(f"Backend Routes:  {report.get('backend_routes', 0)}")

    openapi_info = report.get("openapi_info")
    if openapi_info:
        lines.append(f"OpenAPI Spec:    {openapi_info.get('title')} v{openapi_info.get('version')} ({openapi_info.get('operations_count')} operations)")

    findings = report.get("findings", [])
    disagreements = report.get("openapi_disagreements", [])
    total_issues = len(findings) + len(disagreements)

    lines.append(f"Source Findings: {len(findings)}")
    lines.append(f"Spec Mismatches: {len(disagreements)}")
    lines.append("-" * 70)

    if not total_issues:
        lines.append("[CLEAN] Zero contract mismatches or OpenAPI drift detected!")
    else:
        if findings:
            lines.append("\n[Source Code Findings]")
            for idx, f in enumerate(findings, 1):
                rule = f.get("rule_id", "UNKNOWN")
                sev = f.get("severity", "medium").upper()
                title = f.get("title", "Finding")
                msg = f.get("message", "")
                conf = int(f.get("confidence", 1.0) * 100)
                lines.append(f"  {idx}. [{rule}] ({sev}, {conf}%) {title}")
                lines.append(f"     Message: {msg}")
                for ev in f.get("evidence", []):
                    lines.append(f"     Evidence ({ev.get('role')}): {ev.get('file')}:{ev.get('line')}")
                rec = f.get("recommendation")
                if rec:
                    lines.append(f"     Recommendation: {rec}")

        if disagreements:
            lines.append("\n[OpenAPI Specification Disagreements]")
            for idx, d in enumerate(disagreements, 1):
                rule = d.get("rule_id", "OAS")
                sev = d.get("severity", "medium").upper()
                title = d.get("title", "Disagreement")
                msg = d.get("message", "")
                lines.append(f"  {idx}. [{rule}] ({sev}) {title}")
                lines.append(f"     Message: {msg}")
                for ev in d.get("evidence", []):
                    lines.append(f"     Evidence ({ev.get('role')}): {ev.get('file')}:{ev.get('line')}")

    lines.append("=" * 70)
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "pr":
        from .pr_cli import main as pr_main
        return pr_main(argv[1:])

    parser = argparse.ArgumentParser(
        prog="ghostflow",
        description="GhostFlow — Local-first frontend/backend API contract analyzer and PR intelligence engine",
    )
    parser.add_argument(
        "project_path",
        nargs="?",
        default=".",
        help="Path to project directory to scan (default: current working directory)",
    )
    parser.add_argument(
        "--openapi",
        dest="openapi_path",
        default=None,
        help="Path to OpenAPI / Swagger specification file (JSON or YAML)",
    )
    parser.add_argument(
        "--no-auto-detect-openapi",
        dest="auto_detect_openapi",
        action="store_false",
        default=True,
        help="Disable automatic discovery of OpenAPI specs in project",
    )
    parser.add_argument(
        "--format",
        dest="format",
        choices=["text", "json"],
        default="text",
        help="Output format: text (default) or json",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        default=False,
        help="Exit with non-zero exit code (1) if contract findings or disagreements are detected",
    )

    args = parser.parse_args(argv)

    target_path = Path(args.project_path).expanduser().resolve()
    if not target_path.exists() or not target_path.is_dir():
        sys.stderr.write(f"Error: Target directory '{args.project_path}' does not exist or is not a directory.\n")
        return 2

    try:
        report = scan_project(
            str(target_path),
            openapi_path=args.openapi_path,
            auto_detect_openapi=args.auto_detect_openapi,
        )
    except Exception as exc:
        sys.stderr.write(f"Scan failed: {exc}\n")
        return 2

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(format_text_report(report))

    findings_count = len(report.get("findings", []))
    disagreements_count = len(report.get("openapi_disagreements", []))
    total_issues = findings_count + disagreements_count

    if args.fail_on_findings and total_issues > 0:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
