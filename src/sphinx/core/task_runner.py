"""Sphinx task runner — task CRUD and investigation trigger."""

from __future__ import annotations

import logging
import threading
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from sphinx.core.auth import CurrentUser, check_case_access
from sphinx.core.db import get_cursor
from sphinx.core.models import TaskCreate, TaskOut

log = logging.getLogger(__name__)

router = APIRouter(prefix="/cases/{case_id}/tasks", tags=["tasks"])

_require_analyst = CurrentUser(required_role="analyst")


@router.get("", response_model=list[TaskOut])
async def list_tasks(case_id: str, user=Depends(_require_analyst)):
    """List all tasks for a case."""
    check_case_access(user, case_id)
    with get_cursor() as cur:
        cur.execute(
            "SELECT * FROM tasks WHERE case_id = %s ORDER BY created_at DESC",
            (case_id,),
        )
        return cur.fetchall()


@router.post("", response_model=TaskOut, status_code=status.HTTP_201_CREATED)
async def create_task(case_id: str, body: TaskCreate, user=Depends(_require_analyst)):
    """Create a new investigation task."""
    check_case_access(user, case_id)
    with get_cursor() as cur:
        cur.execute(
            """INSERT INTO tasks (case_id, title, description, assigned_to)
               VALUES (%s, %s, %s, %s)
               RETURNING *""",
            (case_id, body.title, body.description, user.get("sub")),
        )
        row = cur.fetchone()
        cur.connection.commit()
        return row


@router.get("/{task_id}", response_model=TaskOut)
async def get_task(case_id: str, task_id: int, user=Depends(_require_analyst)):
    """Get a single task."""
    check_case_access(user, case_id)
    with get_cursor() as cur:
        cur.execute(
            "SELECT * FROM tasks WHERE id = %s AND case_id = %s",
            (task_id, case_id),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Task not found")
        return row


@router.post("/{task_id}/run")
async def run_task_endpoint(
    case_id: str, task_id: int, request: Request, user=Depends(_require_analyst)
):
    """Trigger the RLM investigation loop for a task.

    Runs pre-computation first, then starts the loop in a background thread.
    Returns immediately with status.
    """
    check_case_access(user, case_id)
    settings = request.app.state.settings
    task_mode = user.get("mode", "investigator")
    task_source_case_ids = user.get("source_case_ids", [])

    # Verify task exists and is pending
    with get_cursor() as cur:
        cur.execute(
            "SELECT * FROM tasks WHERE id = %s AND case_id = %s",
            (task_id, case_id),
        )
        task = cur.fetchone()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        if task["status"] == "running":
            raise HTTPException(status_code=409, detail="Task already running")

    # Mint a scoped JWT for the LLM agent
    from sphinx.core.auth import create_llm_task_token
    llm_token = create_llm_task_token(
        settings,
        case_id=case_id,
        task_id=task_id,
        mode=task_mode,
        source_case_ids=task_source_case_ids,
    )
    log.info("Minted scoped LLM JWT for task %d (mode=%s, cases=%s)",
             task_id, task_mode,
             task_source_case_ids if task_mode == "correlator" else [case_id])

    # Run in background thread
    def _run():
        from sphinx.core.precompute import run_precompute
        from sphinx.core.rlm_loop import run_task, _update_task_status

        try:
            # In correlator mode, precompute per-case AND cross-case
            if task_mode == "correlator" and task_source_case_ids:
                for src_id in task_source_case_ids:
                    log.info("Pre-computing for source case %s, task %d", src_id, task_id)
                    run_precompute(src_id, task_id)
                # Cross-case precompute (shared IOCs, signatures, MITRE overlap)
                from sphinx.core.precompute import run_precompute_cross_case
                log.info("Running cross-case precompute for %d source cases", len(task_source_case_ids))
                run_precompute_cross_case(task_source_case_ids, case_id, task_id)
            else:
                log.info("Pre-computing for case %s, task %d", case_id, task_id)
                run_precompute(case_id, task_id)

            log.info("Starting RLM loop for task %d (mode=%s)", task_id, task_mode)
            result = run_task(
                settings, case_id, task_id,
                mode=task_mode, source_case_ids=task_source_case_ids,
            )
            log.info("Task %d result: %s", task_id, result.get("status"))
        except Exception as e:
            log.error("Task %d failed: %s", task_id, e, exc_info=True)
            try:
                _update_task_status(task_id, "failed")
            except Exception:
                log.error("Failed to update task %d status to failed", task_id)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return {
        "status": "started",
        "task_id": task_id,
        "message": "Investigation started. Poll GET /tasks/{task_id} for status.",
    }


@router.get("/{task_id}/worklog")
async def get_worklog(case_id: str, task_id: int, user=Depends(_require_analyst)):
    """Get the worklog steps for a task (audit trail)."""
    check_case_access(user, case_id)
    with get_cursor() as cur:
        cur.execute(
            """SELECT * FROM worklog_steps
               WHERE task_id = %s
               ORDER BY step_number""",
            (task_id,),
        )
        return cur.fetchall()