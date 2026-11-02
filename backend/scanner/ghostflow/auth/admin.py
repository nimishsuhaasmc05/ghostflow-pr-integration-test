"""GhostFlow Supabase Auth Admin API Client.

Implements administrative identity management (e.g. secure account deletion from auth.users)
using the official Supabase Auth Admin API.
Requires SUPABASE_SERVICE_ROLE_KEY in the backend environment.
The service-role key is strictly server-side and never exposed to the frontend.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
import uuid
from typing import Any, Callable

from fastapi import HTTPException, status

from .config import derive_supabase_project_url, get_service_role_key

logger = logging.getLogger("ghostflow.auth.admin")

# Optional override hook for unit/offline testing
_ADMIN_DELETER_HOOK: Callable[[uuid.UUID], dict[str, Any]] | None = None


def set_admin_deleter_hook(hook: Callable[[uuid.UUID], dict[str, Any]] | None) -> None:
    """Set custom hook for testing Supabase Auth Admin deletion without external network calls."""
    global _ADMIN_DELETER_HOOK
    _ADMIN_DELETER_HOOK = hook


def delete_supabase_auth_user(user_id: uuid.UUID) -> dict[str, Any]:
    """Delete a user account from Supabase Auth (auth.users) via the Auth Admin API.

    Endpoint: DELETE {SUPABASE_URL}/auth/v1/admin/users/{user_id}
    Headers:
      Authorization: Bearer {SUPABASE_SERVICE_ROLE_KEY}
      apikey: {SUPABASE_SERVICE_ROLE_KEY}

    Deleting the user from auth.users triggers the database foreign-key cascade,
    automatically purging public.profiles, user_preferences, projects, scans,
    findings, graphs, and comparisons.

    Raises:
      HTTPException(500): If SUPABASE_SERVICE_ROLE_KEY is unconfigured.
      HTTPException(400-502): If the Supabase Admin API request fails.
    """
    if _ADMIN_DELETER_HOOK is not None:
        logger.info("[Test Hook] Invoking mock admin deleter for user %s", user_id)
        return _ADMIN_DELETER_HOOK(user_id)

    service_role_key = get_service_role_key()
    if not service_role_key:
        logger.error(
            "Account deletion rejected: SUPABASE_SERVICE_ROLE_KEY is not configured in backend environment."
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: SUPABASE_SERVICE_ROLE_KEY is required to delete accounts from Supabase Auth.",
        )

    base_url = derive_supabase_project_url()
    if not base_url:
        logger.error("Account deletion failed: Supabase project URL could not be derived.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: Supabase project URL could not be derived.",
        )

    admin_endpoint = f"{base_url.rstrip('/')}/auth/v1/admin/users/{str(user_id)}"
    headers = {
        "Authorization": f"Bearer {service_role_key}",
        "apikey": service_role_key,
        "Content-Type": "application/json",
    }

    req = urllib.request.Request(admin_endpoint, headers=headers, method="DELETE")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            code = resp.getcode()
            body_bytes = resp.read()
            body_text = body_bytes.decode("utf-8") if body_bytes else "{}"
            result_data = json.loads(body_text) if body_text.strip() else {}

            if 200 <= code < 300:
                logger.info("Successfully deleted Supabase Auth user %s via Admin API", user_id)
                return result_data

            raise HTTPException(
                status_code=code,
                detail=f"Supabase Auth Admin API returned unexpected HTTP status {code}.",
            )

    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        logger.error(
            "Supabase Auth Admin API returned HTTP %s when deleting user %s: %s",
            exc.code,
            user_id,
            err_body,
        )
        try:
            parsed = json.loads(err_body)
            err_msg = parsed.get("msg") or parsed.get("message") or parsed.get("error_description") or err_body
        except Exception:
            err_msg = err_body

        client_status = exc.code if exc.code in (400, 401, 403, 404) else status.HTTP_502_BAD_GATEWAY
        raise HTTPException(
            status_code=client_status,
            detail=f"Supabase Auth Admin deletion failed: {err_msg}",
        ) from exc

    except urllib.error.URLError as exc:
        logger.error("Network error contacting Supabase Auth Admin API: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Network error communicating with Supabase Auth Admin API. Account was not deleted.",
        ) from exc

