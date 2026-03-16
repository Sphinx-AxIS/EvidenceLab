"""Sphinx SSE — Server-Sent Events for live task progress."""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from sphinx.core.auth import CurrentUser, check_case_access
from sphinx.core.db import get_cursor

log = logging.getLogger(__name__)

router = APIRouter(tags=["sse"])

_require_analyst = CurrentUser(required_role="analyst")


@router.get("/cases/{case_id}/tasks/{task_id}/stream")
async def stream_task_progress(
    case_id: str, task_id: int, request: Request,
    user=Depends(_require_analyst),
):
    """SSE endpoint that streams worklog steps as they are written.

    Clients connect and receive events:
      - event: step   (new worklog step recorded)
      - event: status (task status change)
      - event: done   (task completed or failed)
    """
    check_case_access(user, case_id)

    async def event_generator():
        last_step = 0
        last_status = None

        while True:
            # Check if client disconnected
            if await request.is_disconnected():
                break

            # Poll for new steps and status
            with get_cursor() as cur:
                # Get task status
                cur.execute(
                    "SELECT status FROM tasks WHERE id = %s AND case_id = %s",
                    (task_id, case_id),
                )
                task = cur.fetchone()
                if not task:
                    yield _sse_event("error", {"message": "Task not found"})
                    break

                current_status = task["status"]

                # Emit status change
                if current_status != last_status:
                    last_status = current_status
                    yield _sse_event("status", {"status": current_status})

                # Get new steps
                cur.execute(
                    """SELECT step_number, intent, code, stdout, stderr, error,
                              elapsed_s, created_at::text AS created_at
                       FROM worklog_steps
                       WHERE task_id = %s AND step_number > %s
                       ORDER BY step_number""",
                    (task_id, last_step),
                )
                new_steps = cur.fetchall()

                for step in new_steps:
                    last_step = step["step_number"]
                    yield _sse_event("step", {
                        "step_number": step["step_number"],
                        "intent": step["intent"] or "",
                        "code": step["code"] or "",
                        "stdout": (step["stdout"] or "")[:4000],
                        "error": step["error"] or None,
                        "elapsed_s": step["elapsed_s"],
                        "created_at": step["created_at"],
                    })

                # If terminal state, send done and close
                if current_status in ("done", "failed", "cancelled"):
                    # Get finding if done
                    finding_summary = None
                    if current_status == "done":
                        cur.execute(
                            "SELECT title, body FROM findings WHERE task_id = %s ORDER BY created_at DESC LIMIT 1",
                            (task_id,),
                        )
                        finding = cur.fetchone()
                        if finding:
                            finding_summary = finding["body"] or finding["title"]

                    yield _sse_event("done", {
                        "status": current_status,
                        "total_steps": last_step,
                        "finding": finding_summary,
                    })
                    break

            # Poll interval
            await asyncio.sleep(1.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _sse_event(event: str, data: dict) -> str:
    """Format a single SSE event."""
    payload = json.dumps(data, default=str)
    return f"event: {event}\ndata: {payload}\n\n"