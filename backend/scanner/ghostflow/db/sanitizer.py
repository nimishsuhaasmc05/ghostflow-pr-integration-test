"""GhostFlow Sensitive Data Sanitizer.

Removes sensitive local paths, repository credentials, and source secrets
before persistence to cloud databases.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

# Patterns for scrubbing credentials and high-entropy secret tokens from evidence code
_SECRET_PATTERNS = [
    (re.compile(r"ghp_[a-zA-Z0-9]{20,}", re.IGNORECASE), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"bearer\s+[a-zA-Z0-9_\-\.]{15,}", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (
        re.compile(
            r"((?:api[_-]?key|secret|password|auth_token|access_token|private_key)\s*[:=]\s*['\"])[^'\"]+(['\"])",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]\2",
    ),
    (
        re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
        "[REDACTED_JWT]",
    ),
    (
        re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----"),
        "[REDACTED_PRIVATE_KEY]",
    ),
]


def sanitize_project_path(raw_path: str | None) -> str:
    """Sanitize local machine filesystem path for safe cloud persistence.

    Strips local home directories, drive letters, and user workstation details,
    retaining only the safe project directory name or relative identifier.
    """
    if not raw_path:
        return ""
    p_str = raw_path.replace("\\", "/").strip()
    # Strip user directories (Windows / C:\Users\xxx or Linux /home/xxx or macOS /Users/xxx)
    p_str = re.sub(
        r"^[A-Za-z]:/(?:Users|home)/[^/]+/(?:Downloads|Desktop|Documents|projects|workspace|src)/",
        "",
        p_str,
        flags=re.IGNORECASE,
    )
    p_str = re.sub(
        r"^/(?:Users|home)/[^/]+/(?:Downloads|Desktop|Documents|projects|workspace|src)/",
        "",
        p_str,
        flags=re.IGNORECASE,
    )
    # If drive letter or absolute path still present, reduce to the basename
    if re.match(r"^[A-Za-z]:", p_str) or p_str.startswith("/"):
        return Path(raw_path).name
    return p_str


def sanitize_repository_url(url: str | None) -> str | None:
    """Remove embedded access tokens, passwords, and sensitive query params from repository URLs.

    Example:
    https://x-access-token:ghp_secret@github.com/org/repo.git?token=123
    -> https://github.com/org/repo.git
    """
    if not url:
        return None
    try:
        parts = urlsplit(url.strip())
        if not parts.scheme:
            return url.strip()
        netloc = parts.netloc
        if "@" in netloc:
            # Strip embedded user:password or tokens
            _, host = netloc.split("@", 1)
            netloc = host
        # Strip query strings which might carry auth tokens
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except Exception:
        return url


def sanitize_snippet(text: str | None) -> str:
    """Scrub high-entropy tokens, passwords, and authorization headers from source snippets."""
    if not text:
        return ""
    result = text
    for pattern, replacement in _SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def sanitize_evidence_list(evidence_list: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Sanitize all source snippets in a list of Evidence dicts."""
    if not evidence_list:
        return []
    sanitized: list[dict[str, Any]] = []
    for item in evidence_list:
        if isinstance(item, dict):
            item_copy = dict(item)
            if "source" in item_copy and isinstance(item_copy["source"], str):
                item_copy["source"] = sanitize_snippet(item_copy["source"])
            sanitized.append(item_copy)
        else:
            sanitized.append(item)
    return sanitized


def sanitize_details_dict(details: dict[str, Any] | None) -> dict[str, Any]:
    """Recursively scrub sensitive string values in details JSON."""
    if not details:
        return {}
    sanitized: dict[str, Any] = {}
    for k, v in details.items():
        if isinstance(v, str):
            sanitized[k] = sanitize_snippet(v)
        elif isinstance(v, dict):
            sanitized[k] = sanitize_details_dict(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_snippet(elem) if isinstance(elem, str) else elem for elem in v
            ]
        else:
            sanitized[k] = v
    return sanitized

