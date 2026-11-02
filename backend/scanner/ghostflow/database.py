"""GhostFlow Database Connection & Health Verification Layer.

Supports dual-mode persistence:
1. PostgreSQL (e.g., Supabase PostgreSQL or cloud databases) via DATABASE_URL.
2. Local-first SQLite fallback (preserves existing offline workflow).

Guarantees:
- Never prints, logs, or returns plaintext database passwords.
- Performs non-destructive read-only health checks (SELECT 1).
- Does not create or alter tables during connection testing.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

# Attempt to load local environment variables via python-dotenv if present
try:
    from dotenv import load_dotenv

    # Search current directory, project directory, and workspace parent
    _current_dir = Path.cwd()
    _possible_env_paths = [
        _current_dir / ".env",
        _current_dir.parent / ".env",
        Path(__file__).resolve().parent.parent.parent.parent / ".env",
    ]
    for _p in _possible_env_paths:
        if _p.is_file():
            load_dotenv(_p, override=False)
            break
    else:
        load_dotenv(override=False)
except ImportError:
    pass

try:
    import psycopg2
    from psycopg2 import OperationalError, DatabaseError
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    OperationalError = Exception
    DatabaseError = Exception


def get_raw_database_url() -> str | None:
    """Retrieve raw DATABASE_URL from environment if set."""
    val = os.environ.get("DATABASE_URL", "").strip()
    return val if val else None


def redact_database_url(url: str | None) -> str:
    """Mask credentials in a database connection URL for safe logging/display.

    Example:
    postgresql://postgres:secret123@db.supabase.co:5432/postgres
    -> postgresql://postgres:***@db.supabase.co:5432/postgres
    """
    if not url:
        return ""
    try:
        parts = urlsplit(url)
        if not parts.scheme:
            return "[invalid_url_format]"
        netloc = parts.netloc
        if "@" in netloc:
            user_pass, host_port = netloc.split("@", 1)
            if ":" in user_pass:
                user, _ = user_pass.split(":", 1)
                masked_user_pass = f"{user}:***"
            else:
                masked_user_pass = f"{user_pass}:***"
            netloc = f"{masked_user_pass}@{host_port}"
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        # Fallback regex masking
        return re.sub(r"://([^:@]+):([^@]+)@", r"://\1:***@", url)


def get_database_engine() -> str:
    """Detect configured database engine: 'postgresql' or 'sqlite'."""
    url = get_raw_database_url()
    if url and (url.startswith("postgresql://") or url.startswith("postgres://") or url.startswith("postgresql+")):
        return "postgresql"
    return "sqlite"


def parse_pg_connection_parameters(url: str) -> dict[str, Any]:
    """Parse connection parameters from URL for diagnostic display without secret exposure."""
    parts = urlsplit(url)
    user = parts.username or "postgres"
    host = parts.hostname or "localhost"
    port = parts.port or 5432
    dbname = parts.path.lstrip("/") or "postgres"
    return {
        "engine": "postgresql",
        "host": host,
        "port": port,
        "database": dbname,
        "username": user,
        "scheme": parts.scheme,
    }


def check_database_health() -> dict[str, Any]:
    """Perform a safe, read-only health check on the configured database.

    Does not modify or create tables.
    Returns structured health diagnostics with credentials masked.
    """
    engine = get_database_engine()
    raw_url = get_raw_database_url()

    if engine == "sqlite":
        # Check SQLite availability
        from .history import get_history_db_path, init_history_db

        db_path = get_history_db_path()
        try:
            conn = init_history_db(db_path)
            cursor = conn.execute("SELECT sqlite_version();")
            ver = cursor.fetchone()[0]
            conn.close()
            return {
                "status": "connected",
                "engine": "sqlite",
                "database": str(db_path),
                "server_version": f"SQLite {ver}",
                "message": "Local SQLite database is healthy and ready.",
                "url_redacted": f"sqlite:///{db_path}",
            }
        except Exception as exc:
            return {
                "status": "error",
                "engine": "sqlite",
                "database": str(db_path),
                "error": str(exc),
                "message": "Failed to connect to local SQLite database.",
                "url_redacted": f"sqlite:///{db_path}",
            }

    # PostgreSQL Engine
    if not PSYCOPG2_AVAILABLE:
        return {
            "status": "error",
            "engine": "postgresql",
            "error": "psycopg2 driver is not installed in the Python environment.",
            "message": "Please install psycopg2-binary to connect to PostgreSQL.",
            "url_redacted": redact_database_url(raw_url),
        }

    params = parse_pg_connection_parameters(raw_url)
    redacted = redact_database_url(raw_url)

    try:
        # Connect with a strict 5-second timeout and SSL mode required by Supabase
        conn = psycopg2.connect(
            raw_url,
            connect_timeout=5,
            sslmode="require" if "supabase" in (params.get("host") or "") else "prefer",
        )
        with conn.cursor() as cur:
            cur.execute("SELECT version();")
            version_str = cur.fetchone()[0]

        conn.close()
        return {
            "status": "connected",
            "engine": "postgresql",
            "host": params["host"],
            "port": params["port"],
            "database": params["database"],
            "username": params["username"],
            "server_version": version_str.split(",")[0],
            "message": "Successfully connected to PostgreSQL database.",
            "url_redacted": redacted,
        }
    except Exception as exc:
        err_msg = str(exc).strip()
        # Ensure password is scrubbed if it accidentally appears in error message
        if raw_url:
            parts = urlsplit(raw_url)
            if parts.password and parts.password in err_msg:
                err_msg = err_msg.replace(parts.password, "***")

        # Provide actionable context if connection fails
        pooler_hint = None
        if "timeout" in err_msg.lower() or "could not connect" in err_msg.lower():
            if "supabase" in (params.get("host") or ""):
                pooler_hint = (
                    "Direct connection to db.[project-ref].supabase.co uses IPv6. "
                    "If your local network does not support IPv6, configure the Supabase "
                    "Session Pooler instead (e.g. aws-0-[region].pooler.supabase.com on port 5432)."
                )

        return {
            "status": "error",
            "engine": "postgresql",
            "host": params["host"],
            "port": params["port"],
            "database": params["database"],
            "username": params["username"],
            "error": err_msg,
            "pooler_hint": pooler_hint,
            "message": "PostgreSQL connection failed.",
            "url_redacted": redacted,
        }

