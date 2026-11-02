"""GhostFlow Authentication Configuration.

Manages Supabase Auth and JWT verification settings for cloud mode.
Supports automatic derivation of Supabase project endpoints from DATABASE_URL
while preserving zero-credential exposure.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlsplit

from ..database import get_raw_database_url

logger = logging.getLogger("ghostflow.auth.config")


def derive_supabase_project_url() -> str | None:
    """Infer Supabase project URL from SUPABASE_URL or DATABASE_URL host."""
    # 1. Direct explicit environment variables
    explicit_url = os.environ.get("SUPABASE_URL", "").strip() or os.environ.get("VITE_SUPABASE_URL", "").strip()
    if explicit_url:
        return explicit_url.rstrip("/")

    # 2. Derive from DATABASE_URL host if pointing to supabase.co
    raw_db = get_raw_database_url()
    if raw_db:
        try:
            parts = urlsplit(raw_db)
            host = parts.hostname or ""
            # e.g., db.fhhundcyytqsijydtcwd.supabase.co
            if host.endswith(".supabase.co") and host.startswith("db."):
                project_ref = host.split(".")[1]
                return f"https://{project_ref}.supabase.co"
            elif host.endswith(".supabase.co"):
                return f"https://{host}"
        except Exception:
            pass

    return None


def get_jwt_issuer() -> str | None:
    """Get expected JWT issuer claim (iss)."""
    explicit_iss = os.environ.get("SUPABASE_JWT_ISSUER", "").strip()
    if explicit_iss:
        return explicit_iss.rstrip("/")
    base_url = derive_supabase_project_url()
    if base_url:
        return f"{base_url}/auth/v1"
    return None


def get_jwt_audience() -> str:
    """Get expected JWT audience claim (aud). Default: 'authenticated'."""
    return os.environ.get("SUPABASE_JWT_AUDIENCE", "authenticated").strip() or "authenticated"


def get_jwt_secret() -> str | None:
    """Get Supabase JWT verification secret (for symmetric HS256 tokens).

    Required whenever cloud authentication is enabled with HMAC signing.
    """
    secret = (
        os.environ.get("SUPABASE_JWT_SECRET", "").strip()
        or os.environ.get("GHOSTFLOW_TEST_AUTH_SECRET", "").strip()
    )
    return secret if secret else None


def get_jwt_public_key() -> str | None:
    """Get Supabase JWT public key (for asymmetric ES256 / RS256 tokens)."""
    key = (
        os.environ.get("SUPABASE_JWT_PUBLIC_KEY", "").strip()
        or os.environ.get("GHOSTFLOW_TEST_JWT_PUBLIC_KEY", "").strip()
    )
    return key if key else None


def get_jwks_url() -> str | None:
    """Get Supabase JWKS endpoint URL for asymmetric public key retrieval."""
    explicit_jwks = os.environ.get("SUPABASE_JWKS_URL", "").strip()
    if explicit_jwks:
        return explicit_jwks.rstrip("/")
    base_url = derive_supabase_project_url()
    if base_url:
        return f"{base_url}/auth/v1/.well-known/jwks.json"
    return None


def get_service_role_key() -> str | None:
    """Get Supabase service role key (strictly server-side, never exposed to frontend).

    Required for administrative actions like Auth Admin API account deletion.
    """
    key = (
        os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
        or os.environ.get("GHOSTFLOW_TEST_SERVICE_ROLE_KEY", "").strip()
    )
    return key if key else None


def get_anon_key() -> str | None:
    """Get public Supabase anonymous key (safe for browser distribution)."""
    key = os.environ.get("SUPABASE_ANON_KEY", "").strip() or os.environ.get("VITE_SUPABASE_ANON_KEY", "").strip()
    return key if key else None


def is_cloud_auth_enabled() -> bool:
    """Check if cloud persistence / authentication is configured."""
    return bool(derive_supabase_project_url() or get_raw_database_url())


def validate_cloud_auth_configuration() -> list[str]:
    """Validate cloud authentication settings and return diagnostic messages.

    Ensures SEC-AUTH-001 fail-closed posture: cloud mode requires either
    SUPABASE_JWT_SECRET (for symmetric HS256) or SUPABASE_JWT_PUBLIC_KEY / JWKS endpoint (for asymmetric ES256/RS256).
    """
    issues: list[str] = []
    if is_cloud_auth_enabled():
        has_symmetric = bool(get_jwt_secret())
        has_asymmetric = bool(get_jwt_public_key() or get_jwks_url())
        if not (has_symmetric or has_asymmetric):
            issues.append(
                "CRITICAL: Cloud database is configured but neither SUPABASE_JWT_SECRET "
                "nor SUPABASE_JWT_PUBLIC_KEY / JWKS URL is configured. "
                "Cloud requests will fail closed with HTTP 500 to prevent unverified token processing."
            )
        if not get_service_role_key():
            issues.append(
                "NOTICE: SUPABASE_SERVICE_ROLE_KEY is not configured in backend environment. "
                "Admin API operations like complete account deletion from auth.users will fail closed."
            )
    return issues


def get_public_auth_config() -> dict[str, Any]:
    """Return safe public auth configuration for frontend client bootstrapping.

    Never exposes SUPABASE_JWT_SECRET or SUPABASE_SERVICE_ROLE_KEY.
    """
    project_url = derive_supabase_project_url()
    anon_key = get_anon_key()
    has_verification_keys = bool(get_jwt_secret() or get_jwt_public_key() or get_jwks_url())

    return {
        "cloud_enabled": is_cloud_auth_enabled(),
        "supabase_url": project_url,
        "anon_key_configured": bool(anon_key),
        "jwt_signature_verification_active": has_verification_keys,
        "auth_provider": "supabase",
    }
