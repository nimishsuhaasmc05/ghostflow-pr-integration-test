"""GhostFlow GitHub Pull Request Commenter.
=========================================
Posts or updates Pull Request comments using the official GitHub REST API.
Prevents comment spam by detecting and updating existing GhostFlow reports.

Guarantees:
- Never prints or leaks GitHub tokens in stdout, stderr, or exceptions.
- Zero third-party dependencies (uses python standard library urllib).
- Graceful error handling for missing permissions or network timeouts.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any
import urllib.error
import urllib.request

from .pr_report import MARKER_TAG

logger = logging.getLogger("ghostflow.pr_commenter")


def mask_token(token: str | None) -> str:
    """Mask token safely for logging."""
    if not token:
        return "[NONE]"
    if len(token) <= 8:
        return "***"
    return f"{token[:4]}...{token[-4:]}"


def find_existing_ghostflow_comment(
    repo: str,
    pr_number: int | str,
    token: str,
    api_url: str = "https://api.github.com",
) -> int | None:
    """Find existing GhostFlow PR comment ID containing MARKER_TAG."""
    url = f"{api_url.rstrip('/')}/repos/{repo}/issues/{pr_number}/comments?per_page=100"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "GhostFlow-PR-Intelligence/0.4.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            if resp.status == 200:
                body = resp.read().decode("utf-8")
                comments = json.loads(body)
                if isinstance(comments, list):
                    for c in comments:
                        if isinstance(c, dict) and MARKER_TAG in c.get("body", ""):
                            return c.get("id")
    except Exception as e:
        logger.warning(f"Failed to query existing PR comments on {repo}#{pr_number}: {e}")

    return None


def post_or_update_pr_comment(
    repo: str,
    pr_number: int | str,
    token: str,
    markdown_body: str,
    api_url: str = "https://api.github.com",
) -> tuple[bool, str, int | None]:
    """Publish report to PR. Updates existing comment if found, else creates new.

    Returns (success: bool, message: str, comment_id: int | None).
    """
    if not token or not repo or not pr_number:
        return False, "Missing required GitHub credentials (token, repository, or PR number).", None

    existing_id = find_existing_ghostflow_comment(repo, pr_number, token, api_url=api_url)

    payload = json.dumps({"body": markdown_body}).encode("utf-8")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "GhostFlow-PR-Intelligence/0.4.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    if existing_id:
        # Update existing comment via PATCH
        url = f"{api_url.rstrip('/')}/repos/{repo}/issues/comments/{existing_id}"
        req = urllib.request.Request(url, data=payload, headers=headers, method="PATCH")
        action = f"updated existing comment #{existing_id}"
    else:
        # Create new comment via POST
        url = f"{api_url.rstrip('/')}/repos/{repo}/issues/{pr_number}/comments"
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        action = "created new comment"

    try:
        with urllib.request.urlopen(req, timeout=15.0) as resp:
            if resp.status in (200, 201):
                body = resp.read().decode("utf-8")
                data = json.loads(body)
                comment_id = data.get("id") or existing_id
                return True, f"Successfully {action} on {repo}#{pr_number}.", comment_id
            return False, f"Unexpected response status {resp.status} while commenting.", existing_id
    except urllib.error.HTTPError as exc:
        err_msg = exc.read().decode("utf-8", errors="replace")
        return False, f"GitHub API HTTP {exc.code} error: {err_msg}", existing_id
    except Exception as exc:
        return False, f"GitHub API network error: {exc}", existing_id

