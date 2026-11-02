"""GhostFlow JWT Validation Layer.

Implements independent, cryptographically secure JWT verification for Supabase Auth.
Validates:
- Signature (via HMAC-SHA256 secret) - STRICT FAIL-CLOSED (SEC-AUTH-001)
- Issuer (iss matches Supabase auth project endpoint)
- Audience (aud == 'authenticated')
- Expiration (exp with standard clock leeway)
- Subject (sub is non-empty and a valid UUID)

Never trusts unverified user claims or frontend-supplied parameters.
Fails closed with HTTP 500 if SUPABASE_JWT_SECRET is unconfigured.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import jwt
from fastapi import HTTPException, status

from .config import (
    get_jwks_url,
    get_jwt_audience,
    get_jwt_issuer,
    get_jwt_public_key,
    get_jwt_secret,
)

logger = logging.getLogger("ghostflow.auth")

_jwks_clients: dict[str, jwt.PyJWKClient] = {}


def get_jwks_client(jwks_url: str) -> jwt.PyJWKClient:
    """Retrieve or initialize a cached PyJWKClient instance."""
    if jwks_url not in _jwks_clients:
        _jwks_clients[jwks_url] = jwt.PyJWKClient(
            jwks_url,
            cache_keys=True,
            max_cached_keys=16,
            cache_jwk_set=True,
            lifespan=3600,
        )
    return _jwks_clients[jwks_url]


class AuthenticationError(HTTPException):
    """Base exception for authentication failures returning HTTP 401."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )


class AuthConfigurationError(HTTPException):
    """Exception for missing server secrets returning HTTP 500 (Fail-Closed)."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
        )


def verify_supabase_jwt(
    token: str,
    secret: Any | None = None,
    public_key: Any | None = None,
    jwks_url: str | None = None,
    expected_issuer: str | None = None,
    expected_audience: str | None = None,
) -> dict[str, Any]:
    """Verify and decode a Supabase JWT token independently.

    STRICT FAIL-CLOSED POLICY (SEC-AUTH-001):
    - Signature verification is NEVER optional.
    - Inspects token algorithm (ES256 / RS256 / HS256).
    - Unsigned ('none') or unsupported algorithms are strictly rejected with AuthenticationError (HTTP 401).
    - If required secret or public key/JWKS is unconfigured, raises AuthConfigurationError (HTTP 500).

    Args:
        token: Raw JWT string (without or with 'Bearer ' prefix).
        secret: Optional HMAC secret or asymmetric key override.
        public_key: Optional public key override for asymmetric tokens.
        jwks_url: Optional JWKS URL override for asymmetric key discovery.
        expected_issuer: Optional issuer override. If omitted, fetched from config.
        expected_audience: Optional audience override. If omitted, fetched from config.

    Returns:
        dict containing verified claims.

    Raises:
        AuthenticationError: On any signature, expiration, audience, issuer or claim failure (401).
        AuthConfigurationError: When signing keys or secrets are missing (500).
    """
    if not token or not isinstance(token, str):
        raise AuthenticationError("Missing or invalid authorization token.")

    clean_token = token.strip()
    if clean_token.lower().startswith("bearer "):
        clean_token = clean_token[7:].strip()

    if not clean_token:
        raise AuthenticationError("Empty authorization token.")

    try:
        unverified_header = jwt.get_unverified_header(clean_token)
    except Exception as exc:
        raise AuthenticationError(f"Malformed authorization token header: {exc}") from exc

    alg = unverified_header.get("alg")
    if not alg or str(alg).lower() == "none":
        raise AuthenticationError("Unsecured tokens ('none' algorithm) are strictly forbidden.")

    supported_hmac = {"HS256", "HS384", "HS512"}
    supported_asymmetric = {"ES256", "ES384", "ES512", "RS256", "RS384", "RS512"}

    if alg not in supported_hmac and alg not in supported_asymmetric:
        raise AuthenticationError(f"Unsupported signing algorithm: '{alg}'.")

    target_audience = expected_audience if expected_audience is not None else get_jwt_audience()
    target_issuer = expected_issuer if expected_issuer is not None else get_jwt_issuer()

    signing_key: Any = None

    if alg in supported_hmac:
        verification_secret = secret if secret is not None else get_jwt_secret()
        if not verification_secret:
            logger.error(
                "Symmetric JWT verification attempted but SUPABASE_JWT_SECRET is not configured in backend environment."
            )
            raise AuthConfigurationError(
                "Server authentication configuration error: SUPABASE_JWT_SECRET is required. "
                "Cloud requests fail closed until the secret is configured."
            )
        signing_key = verification_secret

    elif alg in supported_asymmetric:
        if public_key is not None:
            signing_key = public_key
        elif secret is not None:
            signing_key = secret
        elif get_jwt_public_key():
            signing_key = get_jwt_public_key()
        else:
            resolved_jwks = jwks_url or get_jwks_url()
            if resolved_jwks:
                try:
                    jwks_client = get_jwks_client(resolved_jwks)
                    signing_jwk = jwks_client.get_signing_key_from_jwt(clean_token)
                    signing_key = signing_jwk.key
                except Exception as exc:
                    logger.error(f"Failed to fetch or resolve JWKS key from {resolved_jwks}: {exc}")
                    raise AuthenticationError(f"Unable to verify token via JWKS: {exc}") from exc
            else:
                logger.error(
                    "Asymmetric JWT received but neither SUPABASE_JWT_PUBLIC_KEY nor JWKS URL is configured."
                )
                raise AuthConfigurationError(
                    "Server authentication configuration error: Public key or JWKS URL is required for asymmetric tokens. "
                    "Cloud requests fail closed until configured."
                )

    # Signature verification is ALWAYS mandatory
    decode_options: dict[str, Any] = {
        "verify_signature": True,
        "verify_exp": True,
        "verify_iat": True,
        "verify_aud": False,  # We validate audience explicitly below for precise error messages
        "verify_iss": False,  # We validate issuer explicitly below for precise error messages
    }

    try:
        claims = jwt.decode(
            clean_token,
            key=signing_key,
            algorithms=[alg],
            options=decode_options,
            leeway=10,  # 10s clock skew tolerance
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("Token expired.") from exc
    except jwt.InvalidSignatureError as exc:
        raise AuthenticationError("Invalid token signature.") from exc
    except jwt.ImmatureSignatureError as exc:
        raise AuthenticationError("Token not yet active.") from exc
    except jwt.DecodeError as exc:
        raise AuthenticationError(f"Malformed authorization token: {exc}") from exc
    except Exception as exc:
        raise AuthenticationError(f"Token validation failed: {exc}") from exc

    # 1. Validate audience (aud)
    aud_claim = claims.get("aud")
    if isinstance(aud_claim, list):
        if target_audience not in aud_claim:
            raise AuthenticationError(
                f"Invalid token audience. Expected '{target_audience}', got {aud_claim}."
            )
    elif aud_claim != target_audience:
        raise AuthenticationError(
            f"Invalid token audience. Expected '{target_audience}', got '{aud_claim}'."
        )

    # 2. Validate issuer (iss) if configured
    iss_claim = claims.get("iss")
    if target_issuer:
        norm_target_iss = target_issuer.rstrip("/")
        norm_actual_iss = str(iss_claim or "").rstrip("/")
        if norm_actual_iss != norm_target_iss:
            raise AuthenticationError(
                f"Invalid token issuer. Expected '{norm_target_iss}', got '{norm_actual_iss}'."
            )

    # 3. Validate subject (sub)
    sub_claim = claims.get("sub")
    if not sub_claim:
        raise AuthenticationError("Missing token subject (sub).")

    try:
        uuid.UUID(str(sub_claim))
    except (ValueError, TypeError, AttributeError) as exc:
        raise AuthenticationError(f"Invalid token subject: '{sub_claim}' is not a valid UUID.") from exc

    return claims
