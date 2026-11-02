"""GhostFlow Authentication Package."""

from .admin import delete_supabase_auth_user, set_admin_deleter_hook
from .config import (
    derive_supabase_project_url,
    get_anon_key,
    get_jwt_audience,
    get_jwt_issuer,
    get_jwt_secret,
    get_public_auth_config,
    get_service_role_key,
    is_cloud_auth_enabled,
    validate_cloud_auth_configuration,
)
from .dependencies import (
    get_authenticated_db,
    get_current_user,
    get_optional_user,
)
from .jwt_validator import (
    AuthConfigurationError,
    AuthenticationError,
    verify_supabase_jwt,
)
from .models import AuthenticatedUser
from .routes import auth_router, cloud_router

__all__ = [
    "AuthenticationError",
    "AuthConfigurationError",
    "AuthenticatedUser",
    "verify_supabase_jwt",
    "get_current_user",
    "get_optional_user",
    "get_authenticated_db",
    "delete_supabase_auth_user",
    "set_admin_deleter_hook",
    "auth_router",
    "cloud_router",
    "get_public_auth_config",
    "is_cloud_auth_enabled",
    "validate_cloud_auth_configuration",
    "get_jwt_issuer",
    "get_jwt_audience",
    "get_jwt_secret",
    "get_service_role_key",
    "get_anon_key",
    "derive_supabase_project_url",
]
