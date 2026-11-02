"""GhostFlow PR Intelligence CLI.
================================
Headless CLI entry point for executing Pull Request intelligence and quality gates.
Designed for GitHub Actions and terminal CI/CD pipelines.

Usage:
  ghostflow pr [project_path] --base main --mode enforce --fail-on high
  python -m ghostflow.pr_cli [project_path] --mode report
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import Sequence

# Ensure scanner package directory takes priority over any workspace directory named 'ghostflow'
_scanner_pkg_root = str(Path(__file__).resolve().parent.parent)
if not sys.path or sys.path[0] != _scanner_pkg_root:
    sys.path.insert(0, _scanner_pkg_root)

from .pr_intelligence import (
    analyze_pull_request,
    QualityGateConfig,
    PRAnalysisResult,
)
from .pr_report import generate_pr_markdown_report
from .pr_commenter import post_or_update_pr_comment, mask_token


def _detect_pr_number_and_repo(
    cli_pr: int | None,
    cli_repo: str | None,
) -> tuple[int | None, str | None]:
    """Detect PR number and repository from CLI flags, environment, or event JSON."""
    pr_number = cli_pr
    repo = cli_repo or os.environ.get("GITHUB_REPOSITORY")

    # 1. From GITHUB_EVENT_PATH (standard in GitHub Actions)
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and Path(event_path).is_file():
        try:
            with open(event_path, "r", encoding="utf-8") as f:
                event_data = json.load(f)
                if not pr_number and "pull_request" in event_data:
                    pr_number = event_data["pull_request"].get("number")
                if not repo and "repository" in event_data:
                    repo = event_data["repository"].get("full_name")
        except Exception:
            pass

    # 2. From GITHUB_REF (e.g. refs/pull/42/merge or refs/pull/42/head)
    if not pr_number:
        gh_ref = os.environ.get("GITHUB_REF", "")
        m = re.match(r"^refs/pull/(\d+)/(?:merge|head)$", gh_ref)
        if m:
            pr_number = int(m.group(1))

    return pr_number, repo


def main(argv: Sequence[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="ghostflow-pr",
        description="GhostFlow — GitHub Pull Request Intelligence & Quality Gate",
    )
    parser.add_argument(
        "project_path",
        nargs="?",
        default=".",
        help="Path to project directory to scan (default: current working directory)",
    )
    parser.add_argument(
        "--base",
        dest="base_ref",
        default=os.environ.get("GITHUB_BASE_REF") or os.environ.get("GHOSTFLOW_BASE_REF"),
        help="Base branch, tag, or commit to compare against (e.g. main, origin/main)",
    )
    parser.add_argument(
        "--head",
        dest="head_ref",
        default=os.environ.get("GITHUB_HEAD_REF") or "HEAD",
        help="Head revision to scan (default: HEAD)",
    )
    parser.add_argument(
        "--mode",
        dest="mode",
        choices=["report", "warn", "enforce", "report-only"],
        default=os.environ.get("GHOSTFLOW_MODE", "report"),
        help="Quality gate mode: 'report' (default, non-blocking), 'warn' (warning, non-blocking), or 'enforce' (blocks PR on defect)",
    )
    parser.add_argument(
        "--fail-on",
        dest="fail_on",
        default=os.environ.get("GHOSTFLOW_FAIL_ON", "high"),
        help="Defect severity or rule list to trigger quality gate failure (e.g. 'high', 'medium', or 'API001,DB001,DB007')",
    )
    parser.add_argument(
        "--only-new",
        dest="only_new",
        action="store_true",
        default=True,
        help="Only evaluate quality gate against newly introduced findings in this PR (default: True)",
    )
    parser.add_argument(
        "--include-existing",
        dest="only_new",
        action="store_false",
        help="Evaluate quality gate against all findings (including pre-existing baseline issues)",
    )
    parser.add_argument(
        "--openapi",
        dest="openapi_path",
        default=os.environ.get("GHOSTFLOW_OPENAPI_PATH"),
        help="Path to OpenAPI specification file (optional)",
    )
    parser.add_argument(
        "--no-auto-detect-openapi",
        dest="auto_detect_openapi",
        action="store_false",
        default=True,
        help="Disable automatic OpenAPI specification discovery",
    )
    parser.add_argument(
        "--post-comment",
        dest="post_comment",
        action="store_true",
        default=os.environ.get("GHOSTFLOW_POST_COMMENT", "true").lower() in ("true", "1", "yes"),
        help="Publish or update report comment on GitHub Pull Request",
    )
    parser.add_argument(
        "--no-post-comment",
        dest="post_comment",
        action="store_false",
        help="Do not publish comment to GitHub PR",
    )
    parser.add_argument(
        "--token",
        dest="github_token",
        default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub Personal Access Token or GITHUB_TOKEN (defaults to $GITHUB_TOKEN)",
    )
    parser.add_argument(
        "--repo",
        dest="github_repo",
        default=os.environ.get("GITHUB_REPOSITORY"),
        help="GitHub repository in 'owner/repo' format (defaults to $GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--pr-number",
        dest="pr_number",
        type=int,
        default=None,
        help="Pull Request number (auto-detected from GitHub environment if omitted)",
    )
    parser.add_argument(
        "--output-file",
        dest="output_file",
        default=None,
        help="Write markdown PR comment report to specified file path",
    )
    parser.add_argument(
        "--json-output",
        dest="json_output",
        default=None,
        help="Write structured JSON analysis result to specified file path",
    )

    args = parser.parse_args(argv)

    target_path = Path(args.project_path).expanduser().resolve()
    if not target_path.is_dir():
        sys.stderr.write(f"Error: Target directory '{args.project_path}' does not exist or is not a directory.\n")
        return 2

    gate_config = QualityGateConfig(
        mode=args.mode,
        fail_on=args.fail_on,
        only_new=args.only_new,
    )

    # Execute PR intelligence analysis
    try:
        result = analyze_pull_request(
            project_path=target_path,
            base_ref=args.base_ref,
            head_ref=args.head_ref,
            openapi_path=args.openapi_path,
            auto_detect_openapi=args.auto_detect_openapi,
            gate_config=gate_config,
        )
    except Exception as exc:
        sys.stderr.write(f"GhostFlow PR Analysis failed: {exc}\n")
        return 2

    # Generate Markdown Report
    markdown_report = generate_pr_markdown_report(result)

    # Print to console
    print(markdown_report)

    # Write output markdown file if requested
    if args.output_file:
        try:
            out_p = Path(args.output_file).expanduser().resolve()
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(markdown_report, encoding="utf-8")
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to write markdown output to {args.output_file}: {e}\n")

    # Write JSON output if requested
    if args.json_output:
        try:
            json_p = Path(args.json_output).expanduser().resolve()
            json_p.parent.mkdir(parents=True, exist_ok=True)
            json_p.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to write JSON output to {args.json_output}: {e}\n")

    # Populate GitHub Step Summary if running in GitHub Actions
    step_summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary_path:
        try:
            with open(step_summary_path, "a", encoding="utf-8") as ss_file:
                ss_file.write("\n\n" + markdown_report + "\n")
        except Exception as e:
            sys.stderr.write(f"Notice: Failed to write to GITHUB_STEP_SUMMARY: {e}\n")

    # Handle PR Commenting via GitHub REST API
    pr_number, repo = _detect_pr_number_and_repo(args.pr_number, args.github_repo)
    if args.post_comment and args.github_token and pr_number and repo:
        success, comment_msg, comment_id = post_or_update_pr_comment(
            repo=repo,
            pr_number=pr_number,
            token=args.github_token,
            markdown_body=markdown_report,
        )
        if success:
            print(f"\n[GhostFlow GitHub PR] {comment_msg} (Comment ID: {comment_id})")
        else:
            sys.stderr.write(f"\n[GhostFlow GitHub PR Warning] {comment_msg}\n")
    elif args.post_comment and not args.github_token:
        # Not an error; e.g. run locally or GITHUB_TOKEN not forwarded
        sys.stderr.write("\n[GhostFlow Notice] GITHUB_TOKEN not provided; skipping PR comment posting.\n")

    # Emit GitHub Workflow command annotations
    if result.gate_verdict == "FAIL":
        sys.stderr.write(f"\n::error title=GhostFlow Quality Gate Failed::{result.gate_explanation}\n")
    elif result.gate_verdict == "WARN":
        sys.stderr.write(f"\n::warning title=GhostFlow Quality Gate Warning::{result.gate_explanation}\n")

    # Set GitHub Actions output parameters if GITHUB_OUTPUT is defined
    gh_output_path = os.environ.get("GITHUB_OUTPUT")
    if gh_output_path:
        try:
            with open(gh_output_path, "a", encoding="utf-8") as out_file:
                out_file.write(f"verdict={result.gate_verdict}\n")
                out_file.write(f"findings-count={len(result.head_findings)}\n")
                out_file.write(f"new-findings-count={len(result.new_findings)}\n")
                out_file.write(f"resolved-findings-count={len(result.resolved_findings)}\n")
                out_file.write(f"database-findings-count={len(result.database_findings)}\n")
        except Exception:
            pass

    # Exit code based on quality gate verdict
    if result.gate_verdict == "FAIL":
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

