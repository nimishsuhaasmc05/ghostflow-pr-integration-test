"""FastAPI Dependencies for GhostFlow Authentication & Scoped Database Sessions."""

from __future__ import annotations

import logging
import uuid
from typing import Generator

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..database import get_database_engine
from ..db.session import get_session_factory
from .jwt_validator import AuthenticationError, verify_supabase_jwt
from .models import AuthenticatedUser

logger = logging.getLogger("ghostflow.auth")

security_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(security_bearer),
) -> AuthenticatedUser:
    """Dependency that verifies incoming Supabase JWT and returns AuthenticatedUser.

    Rejects requests with missing, expired, or invalid tokens with HTTP 401.
    Never trusts frontend-supplied user IDs or unverified claims.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    claims = verify_supabase_jwt(credentials.credentials)

    sub_str = claims.get("sub")
    user_id = uuid.UUID(str(sub_str))
    email = claims.get("email")
    role = claims.get("role", "authenticated")

    return AuthenticatedUser(
        id=user_id,
        email=email,
        role=role,
        claims=claims,
    )


def get_optional_user(
    credentials: HTTPAuthorizationCredentials | None = Security(security_bearer),
) -> AuthenticatedUser | None:
    """Dependency for dual-mode endpoints that support both anonymous local mode and cloud mode."""
    if credentials is None or not credentials.credentials:
        return None
    return get_current_user(credentials)


def get_authenticated_db(
    user: AuthenticatedUser = Depends(get_current_user),
) -> Generator[Session, None, None]:
    """Dependency yielding a SQLAlchemy Session scoped to the authenticated user.

    In PostgreSQL mode:
    - Sets local role to 'authenticated' (enforcing RLS policies).
    - Sets 'request.jwt.claim.sub' parameter to the user's UUID.
    - Sets 'request.jwt.claim.role' to 'authenticated'.
    - Uses local transaction-scoped variables so claims cannot leak between requests.
    """
    factory = get_session_factory()
    session = factory()
    is_postgres = get_database_engine() == "postgresql"

    try:
        if is_postgres:
            # Set request-scoped RLS role and JWT claims within the current transaction
            session.execute(text("SET LOCAL ROLE authenticated;"))
            session.execute(
                text("SELECT set_config('request.jwt.claim.sub', :user_id, true);"),
                {"user_id": str(user.id)},
            )
            session.execute(
                text("SELECT set_config('request.jwt.claim.role', :role, true);"),
                {"role": user.role},
            )
            if user.email:
                session.execute(
                    text("SELECT set_config('request.jwt.claim.email', :email, true);"),
                    {"email": user.email},
                )
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
