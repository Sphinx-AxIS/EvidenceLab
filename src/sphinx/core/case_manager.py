"""Sphinx case management — CRUD API routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status

from sphinx.core.auth import CurrentUser, check_case_access
from sphinx.core.db import get_cursor
from sphinx.core.models import CaseCreate, CaseOut, CaseUpdate

router = APIRouter(prefix="/cases", tags=["cases"])

_require_analyst = CurrentUser(required_role="analyst")
_require_manager = CurrentUser(required_role="case_manager")


@router.get("", response_model=list[CaseOut])
async def list_cases(user=Depends(_require_analyst)):
    """List cases the current user has access to."""
    with get_cursor() as cur:
        role = user.get("role", "")
        if role in ("admin", "case_manager"):
            cur.execute(
                "SELECT * FROM cases ORDER BY created_at DESC"
            )
        else:
            case_ids = user.get("case_ids", [])
            if not case_ids:
                return []
            cur.execute(
                "SELECT * FROM cases WHERE id = ANY(%s) ORDER BY created_at DESC",
                (case_ids,),
            )
        return cur.fetchall()


@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
async def create_case(body: CaseCreate, user=Depends(_require_manager)):
    """Create a new case."""
    with get_cursor() as cur:
        cur.execute(
            """INSERT INTO cases (id, name, description, home_net, victim_ips)
               VALUES (%s, %s, %s, %s, %s)
               RETURNING *""",
            (body.id, body.name, body.description, body.home_net, body.victim_ips),
        )
        row = cur.fetchone()
        cur.connection.commit()
        return row


@router.get("/{case_id}", response_model=CaseOut)
async def get_case(case_id: str, user=Depends(_require_analyst)):
    """Get a single case by ID."""
    check_case_access(user, case_id)
    with get_cursor() as cur:
        cur.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")
        return row


@router.patch("/{case_id}", response_model=CaseOut)
async def update_case(case_id: str, body: CaseUpdate, user=Depends(_require_manager)):
    """Update case fields."""
    updates = body.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    set_clauses = []
    values = []
    for key, val in updates.items():
        set_clauses.append(f"{key} = %s")
        values.append(val)
    set_clauses.append("updated_at = now()")
    values.append(case_id)

    sql = f"UPDATE cases SET {', '.join(set_clauses)} WHERE id = %s RETURNING *"
    with get_cursor() as cur:
        cur.execute(sql, values)
        row = cur.fetchone()
        cur.connection.commit()
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")
        return row


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case(case_id: str, user=Depends(CurrentUser(required_role="admin"))):
    """Delete a case (admin only)."""
    with get_cursor() as cur:
        cur.execute("DELETE FROM cases WHERE id = %s", (case_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Case not found")
        cur.connection.commit()