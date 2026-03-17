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
    correlation_case_id: str = "",
    source_case_ids: list[str] | None = None,
) -> str:
    """Create a signed JWT."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "case_ids": case_ids or [],
        "mode": mode,
        "correlation_case_id": correlation_case_id,
        "source_case_ids": source_case_ids or [],
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
        credentials: HTTPAuthorizationCredentials | None = Depends(
            HTTPBearer(auto_error=False)
        ),
    ) -> dict[str, Any]:
        settings: Settings = request.app.state.settings

        # Try Bearer token first, then fall back to sphinx_token cookie
        if credentials and credentials.credentials:
            token = credentials.credentials
        else:
            token = request.cookies.get("sphinx_token")
            if not token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                )

        user = decode_token(settings, token)

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


def create_llm_task_token(
    settings: Settings,
    *,
    case_id: str,
    task_id: int,
    mode: str = "investigator",
    source_case_ids: list[str] | None = None,
) -> str:
    """Mint a short-lived JWT for the llm_agent service account, scoped to
    the cases required by this task.

    - Investigator mode: case_ids = [case_id]
    - Correlator mode:  case_ids = source_case_ids
    """
    from sphinx.core.db import get_cursor

    # Look up the llm_agent user id
    with get_cursor() as cur:
        cur.execute("SELECT id FROM users WHERE username = 'llm_agent'")
        row = cur.fetchone()
        if not row:
            raise RuntimeError("llm_agent service account not found — run bootstrap first")
        agent_user_id = row["id"]

    if mode == "correlator" and source_case_ids:
        scoped_case_ids = source_case_ids
    else:
        scoped_case_ids = [case_id]

    # Short-lived token — expires after max task duration (30 min default)
    now = datetime.now(timezone.utc)
    payload = {
        "sub": agent_user_id,
        "role": "llm_agent",
        "case_ids": scoped_case_ids,
        "mode": mode,
        "correlation_case_id": case_id if mode == "correlator" else "",
        "source_case_ids": source_case_ids or [],
        "task_id": task_id,
        "iat": now,
        "exp": now + timedelta(minutes=30),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def check_case_access(user: dict[str, Any], case_id: str) -> None:
    """Raise 403 if the user's JWT doesn't grant access to this case."""
    role = user.get("role", "")
    if role in ("admin", "case_manager"):
        return  # full access

    # In correlator mode, allow access to source cases and the correlation case
    mode = user.get("mode", "investigator")
    if mode == "correlator":
        allowed = set(user.get("source_case_ids", []))
        corr_id = user.get("correlation_case_id", "")
        if corr_id:
            allowed.add(corr_id)
        allowed.update(user.get("case_ids", []))
        if case_id in allowed:
            return

    allowed = user.get("case_ids", [])
    if allowed and case_id not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"No access to case '{case_id}'",
        )