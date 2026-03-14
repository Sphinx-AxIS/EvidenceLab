"""Sphinx auth routes — login, user management."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status

from sphinx.core.auth import (
    CurrentUser,
    create_token,
    hash_password,
    verify_password,
)
from sphinx.core.db import get_cursor
from sphinx.core.models import LoginRequest, TokenResponse, UserCreate, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])

_require_admin = CurrentUser(required_role="admin")


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request):
    """Authenticate and return a JWT."""
    settings = request.app.state.settings
    with get_cursor() as cur:
        cur.execute(
            "SELECT * FROM users WHERE username = %s AND active = true",
            (body.username,),
        )
        user = cur.fetchone()

    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Get assigned case IDs for non-admin/case_manager roles
    case_ids: list[str] = []
    if user["role"] not in ("admin", "case_manager"):
        with get_cursor() as cur:
            cur.execute(
                "SELECT case_id FROM case_assignments WHERE user_id = %s",
                (user["id"],),
            )
            case_ids = [row["case_id"] for row in cur.fetchall()]

    token = create_token(
        settings,
        user_id=user["id"],
        role=user["role"],
        case_ids=case_ids,
    )
    return TokenResponse(access_token=token)


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(body: UserCreate, user=Depends(_require_admin)):
    """Create a new user (admin only)."""
    user_id = str(uuid.uuid4())
    pw_hash = hash_password(body.password)

    with get_cursor() as cur:
        try:
            cur.execute(
                """INSERT INTO users (id, username, password_hash, role)
                   VALUES (%s, %s, %s, %s)
                   RETURNING *""",
                (user_id, body.username, pw_hash, body.role),
            )
            row = cur.fetchone()
            cur.connection.commit()
            return row
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Username '{body.username}' already exists",
            )


@router.get("/users", response_model=list[UserOut])
async def list_users(user=Depends(_require_admin)):
    """List all users (admin only)."""
    with get_cursor() as cur:
        cur.execute("SELECT * FROM users ORDER BY created_at DESC")
        return cur.fetchall()


@router.get("/me", response_model=UserOut)
async def get_current_user(user=Depends(CurrentUser())):
    """Get the currently authenticated user's profile."""
    with get_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = %s", (user["sub"],))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        return row