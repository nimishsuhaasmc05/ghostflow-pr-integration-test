"""GhostFlow Authentication & User Management API Endpoints."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db.models import Profile, Project, Scan, UserPreference
from .admin import delete_supabase_auth_user
from .config import get_public_auth_config
from .dependencies import get_authenticated_db, get_current_user
from .models import AuthenticatedUser

logger = logging.getLogger("ghostflow.auth")

auth_router = APIRouter(prefix="/api/auth", tags=["auth"])


class UpdatePreferencesRequest(BaseModel):
    theme: str | None = Field(None, pattern="^(system|dark|light)$")
    default_scan_mode: str | None = Field(None, pattern="^(deep|fast|advisory)$")
    enable_ai_advisory: bool | None = None
    auto_detect_openapi: bool | None = None


class ProfileResponse(BaseModel):
    id: str
    email: str | None
    full_name: str | None
    avatar_url: str | None
    created_at: str | None


class PreferenceResponse(BaseModel):
    theme: str
    default_scan_mode: str
    enable_ai_advisory: bool
    auto_detect_openapi: bool


class UserMeResponse(BaseModel):
    user_id: str
    email: str | None
    role: str
    profile: ProfileResponse | None
    preferences: PreferenceResponse | None


@auth_router.get("/config")
def get_auth_config_endpoint() -> dict[str, Any]:
    """Safe public auth configuration for frontend initialization."""
    return get_public_auth_config()


@auth_router.get("/me", response_model=UserMeResponse)
def get_current_user_profile(
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> UserMeResponse:
    """Retrieve verified user profile and preferences.

    Identity is strictly derived from the verified Supabase JWT subject.
    Never relies on user-supplied parameters.
    """
    profile = db.query(Profile).filter(Profile.id == user.id).first()
    prefs = db.query(UserPreference).filter(UserPreference.user_id == user.id).first()

    # If profile record has not yet been provisioned by auth trigger (e.g. test environment)
    # create it gracefully
    if profile is None:
        try:
            profile = Profile(
                id=user.id,
                email=user.email or f"{user.id}@ghostflow.local",
                full_name=user.claims.get("user_metadata", {}).get("full_name"),
                avatar_url=user.claims.get("user_metadata", {}).get("avatar_url"),
            )
            db.add(profile)
            db.flush()
        except Exception as exc:
            db.rollback()
            logger.warning("Could not automatically create profile for %s: %s", user.id, exc)
            profile = None

    if profile is not None and prefs is None:
        try:
            prefs = UserPreference(
                id=uuid.uuid4(),
                user_id=user.id,
                theme="system",
                default_scan_mode="deep",
                enable_ai_advisory=False,
                auto_detect_openapi=True,
            )
            db.add(prefs)
            db.flush()
        except Exception as exc:
            db.rollback()
            logger.warning("Could not automatically create preferences for %s: %s", user.id, exc)
            prefs = None

    return UserMeResponse(
        user_id=str(user.id),
        email=user.email,
        role=user.role,
        profile=ProfileResponse(
            id=str(profile.id),
            email=profile.email,
            full_name=profile.full_name,
            avatar_url=profile.avatar_url,
            created_at=profile.created_at.isoformat() if profile and profile.created_at else None,
        ) if profile else None,
        preferences=PreferenceResponse(
            theme=prefs.theme if prefs else "system",
            default_scan_mode=prefs.default_scan_mode if prefs else "deep",
            enable_ai_advisory=prefs.enable_ai_advisory if prefs else False,
            auto_detect_openapi=prefs.auto_detect_openapi if prefs else True,
        ) if prefs else None,
    )


@auth_router.put("/preferences", response_model=PreferenceResponse)
def update_user_preferences(
    body: UpdatePreferencesRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> PreferenceResponse:
    """Update current user's preferences."""
    prefs = db.query(UserPreference).filter(UserPreference.user_id == user.id).first()
    if prefs is None:
        prefs = UserPreference(
            id=uuid.uuid4(),
            user_id=user.id,
            theme=body.theme or "system",
            default_scan_mode=body.default_scan_mode or "deep",
            enable_ai_advisory=bool(body.enable_ai_advisory),
            auto_detect_openapi=body.auto_detect_openapi if body.auto_detect_openapi is not None else True,
        )
        db.add(prefs)
    else:
        if body.theme is not None:
            prefs.theme = body.theme
        if body.default_scan_mode is not None:
            prefs.default_scan_mode = body.default_scan_mode
        if body.enable_ai_advisory is not None:
            prefs.enable_ai_advisory = body.enable_ai_advisory
        if body.auto_detect_openapi is not None:
            prefs.auto_detect_openapi = body.auto_detect_openapi

    db.flush()
    return PreferenceResponse(
        theme=prefs.theme,
        default_scan_mode=prefs.default_scan_mode,
        enable_ai_advisory=prefs.enable_ai_advisory,
        auto_detect_openapi=prefs.auto_detect_openapi,
    )


@auth_router.delete("/account")
def delete_user_account(
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_authenticated_db),
) -> dict[str, Any]:
    """Securely delete the authenticated user's account and associated cloud data.

    Enforces SEC-AUTH-002:
    - User identity derived exclusively from verified JWT subject (user.id).
    - Calls official Supabase Auth Admin API using backend SUPABASE_SERVICE_ROLE_KEY.
    - If the admin deletion fails, an HTTPException is raised and no success is reported.
    - Cascades through public.profiles, user_preferences, projects, scans, findings,
      root_causes, scan_graphs, and scan_comparisons via foreign-key constraints.
    """
    # 1. Official Supabase Auth Admin API deletion
    admin_result = delete_supabase_auth_user(user.id)

    # 2. Purge database records in active session (cascades via foreign keys)
    deleted_count = db.query(Profile).filter(Profile.id == user.id).delete()
    db.flush()

    logger.info("Successfully completed account deletion for user %s", user.id)
    return {
        "status": "deleted",
        "user_id": str(user.id),
        "detail": "User account and all associated cloud data deleted successfully.",
        "admin_result": admin_result,
        "records_affected": deleted_count,
    }


# Cloud persistence routers have been migrated to the ghostflow.cloud package
from ..cloud.projects import cloud_projects_router as cloud_router  # noqa: F401
