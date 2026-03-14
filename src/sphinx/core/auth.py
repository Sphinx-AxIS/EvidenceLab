"""Sphinx JWT authentication and RBAC middleware."""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from sphinx.core.config import Settings

log = logging.getLogger(__name__)

_bearer = HTTPBearer()

# Role hierarchy — higher index = more privileges
ROLES = ("llm_agent", "analyst", "case_manager", "admin")
ROLE_RANK = {role: i for i, role in enumerate(ROLES)}


def hash_password(password: str) -> str:
    """Hash a password with a random salt (SHA-256 + salt)."""
    salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return f"{salt}:{h}"


def verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored salt:hash."""
    salt, expected = stored.split(":", 1)
    h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return secrets.compare_digest(h, expected)


def create_token(
    settings: Settings,
    *,
    user_id: str,
    role: str,
    case_ids: list[str] | None = None,
    mode: str = "investigator",
) -> str:
    """Create a signed JWT."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "case_ids": case_ids or [],
        "mode": mode,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(settings: Settings, token: str) -> dict[str, Any]:
    """Decode and validate a JWT. Raises HTTPException on failure."""
    try:
        payload = jwt.decode(
            token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
        )


class CurrentUser:
    """Dependency that extracts and validates the current user from JWT."""

    def __init__(self, required_role: str | None = None):
        self.required_role = required_role

    async def __call__(
        self,
        request: Request,
        credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    ) -> dict[str, Any]:
        settings: Settings = request.app.state.settings
        user = decode_token(settings, credentials.credentials)

        if self.required_role is not None:
            user_rank = ROLE_RANK.get(user.get("role", ""), -1)
            required_rank = ROLE_RANK.get(self.required_role, 999)
            if user_rank < required_rank:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{user.get('role')}' insufficient — "
                           f"requires '{self.required_role}' or higher",
                )

        return user


def check_case_access(user: dict[str, Any], case_id: str) -> None:
    """Raise 403 if the user's JWT doesn't grant access to this case."""
    role = user.get("role", "")
    if role in ("admin", "case_manager"):
        return  # full access
    allowed = user.get("case_ids", [])
    if allowed and case_id not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"No access to case '{case_id}'",
        )