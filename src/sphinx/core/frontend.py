"""Sphinx frontend — server-side rendered UI routes."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Form, Request, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from sphinx.core.auth import create_token, verify_password
from sphinx.core.db import get_cursor
from sphinx.core.plugin_loader import get_registry

log = logging.getLogger(__name__)

_HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(_HERE / "templates"))

router = APIRouter(prefix="/ui", tags=["ui"])


# ── Helpers ─────────────────────────────────────────

def _get_token(request: Request) -> Optional[str]:
    return request.cookies.get("sphinx_token")


def _get_user(request: Request) -> Optional[dict]:
    """Decode JWT from cookie; return user dict or None."""
    token = _get_token(request)
    if not token:
        return None
    try:
        from sphinx.core.auth import decode_token
        settings = request.app.state.settings
        payload = decode_token(settings, token)
        # Add username from DB for display
        with get_cursor() as cur:
            cur.execute("SELECT username FROM users WHERE id = %s", (payload.get("sub"),))
            row = cur.fetchone()
            payload["username"] = row["username"] if row else "unknown"
        return payload
    except Exception:
        return None


def _require_user(request: Request):
    """Return user dict or raise redirect to login."""
    user = _get_user(request)
    if not user:
        raise _redirect_login()
    return user


def _redirect_login():
    from fastapi.exceptions import HTTPException
    raise HTTPException(status_code=307, headers={"Location": "/ui/login"})


def _ctx(request: Request, user: dict, page: str, case_id: str = "", **extra):
    """Build template context."""
    return {
        "request": request,
        "user": user,
        "active_page": page,
        "case_id": case_id,
        **extra,
    }


# ── Auth pages ──────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@router.post("/login")
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    with get_cursor() as cur:
        cur.execute(
            "SELECT id, username, role, password_hash FROM users WHERE username = %s",
            (username,),
        )
        row = cur.fetchone()

    if not row or not verify_password(password, row["password_hash"]):
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "Invalid username or password",
        })

    settings = request.app.state.settings
    token = create_token(
        settings, user_id=row["id"], role=row["role"],
    )
    response = RedirectResponse(url="/ui/", status_code=303)
    response.set_cookie("sphinx_token", token, httponly=True, max_age=86400)
    return response


@router.get("/logout")
async def logout():
    response = RedirectResponse(url="/ui/login", status_code=303)
    response.delete_cookie("sphinx_token")
    return response


# ── Dashboard ───────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, case_id: str = ""):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        # List cases
        cur.execute("SELECT id, name, status, created_at::text AS created_at FROM cases ORDER BY created_at DESC")
        cases = cur.fetchall()

        summary = {}
        if case_id:
            # Record counts by type
            cur.execute(
                """SELECT record_type, count(*) AS count
                   FROM records WHERE case_id = %s AND record_type != 'worklog_step'
                   GROUP BY record_type ORDER BY count DESC""",
                (case_id,),
            )
            record_counts = cur.fetchall()

            # Task stats
            cur.execute("SELECT count(*) AS n FROM tasks WHERE case_id = %s", (case_id,))
            tasks_total = cur.fetchone()["n"]
            cur.execute("SELECT count(*) AS n FROM tasks WHERE case_id = %s AND status = 'done'", (case_id,))
            tasks_done = cur.fetchone()["n"]

            # Findings count
            cur.execute(
                "SELECT count(*) AS n FROM findings WHERE case_id = %s",
                (case_id,),
            )
            findings_count = cur.fetchone()["n"]

            # Entity count
            cur.execute("SELECT count(*) AS n FROM entities WHERE case_id = %s", (case_id,))
            entity_count = cur.fetchone()["n"]

            # Total records
            total_records = sum(r["count"] for r in record_counts)

            summary = {
                "record_counts": record_counts,
                "tasks_total": tasks_total,
                "tasks_done": tasks_done,
                "findings_count": findings_count,
                "entity_count": entity_count,
                "total_records": total_records,
            }

    # Plugin info
    registry = get_registry()
    plugins = []
    for name, manifest in registry.plugins.items():
        plugins.append({"name": name, "version": manifest.get("version", "?")})
    summary["plugins"] = plugins

    return templates.TemplateResponse("dashboard.html", _ctx(
        request, user, "dashboard", case_id=case_id,
        cases=cases, summary=summary,
    ))


# ── Cases ───────────────────────────────────────────

@router.get("/cases", response_class=HTMLResponse)
async def cases_list(request: Request):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute("SELECT id, name, status, created_at::text AS created_at FROM cases ORDER BY created_at DESC")
        cases = cur.fetchall()

    return templates.TemplateResponse("cases.html", _ctx(request, user, "cases", cases=cases))


@router.get("/cases/new", response_class=HTMLResponse)
async def case_new_form(request: Request):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)
    return templates.TemplateResponse("case_new.html", _ctx(request, user, "cases"))


@router.post("/cases/new")
async def case_new_submit(request: Request, name: str = Form(...), description: str = Form("")):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    import uuid
    case_id = str(uuid.uuid4())
    with get_cursor() as cur:
        cur.execute(
            "INSERT INTO cases (id, name, description, status) VALUES (%s, %s, %s, 'open')",
            (case_id, name, description),
        )
        cur.connection.commit()

    return RedirectResponse(url=f"/ui/?case_id={case_id}", status_code=303)


# ── Records ─────────────────────────────────────────

@router.get("/cases/{case_id}/records", response_class=HTMLResponse)
async def records_list(request: Request, case_id: str, type: str = "", offset: int = 0):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    limit = 50
    with get_cursor() as cur:
        # Available types
        cur.execute(
            "SELECT DISTINCT record_type FROM records WHERE case_id = %s AND record_type != 'worklog_step' ORDER BY record_type",
            (case_id,),
        )
        record_types = [r["record_type"] for r in cur.fetchall()]

        # Query
        where = "case_id = %s AND record_type != 'worklog_step'"
        params = [case_id]
        if type:
            where += " AND record_type = %s"
            params.append(type)

        cur.execute(f"SELECT count(*) AS n FROM records WHERE {where}", params)
        total = cur.fetchone()["n"]

        cur.execute(
            f"SELECT id, record_type, ts::text AS ts FROM records WHERE {where} ORDER BY ts DESC NULLS LAST LIMIT %s OFFSET %s",
            params + [limit, offset],
        )
        records = cur.fetchall()

    return templates.TemplateResponse("records.html", _ctx(
        request, user, "records", case_id=case_id,
        records=records, record_types=record_types,
        type_filter=type, total=total, offset=offset, limit=limit,
    ))


@router.get("/cases/{case_id}/records/{record_id}", response_class=HTMLResponse)
async def record_detail(request: Request, case_id: str, record_id: str):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            "SELECT id, record_type, ts::text AS ts, raw FROM records WHERE id = %s AND case_id = %s",
            (record_id, case_id),
        )
        record = cur.fetchone()
        if not record:
            return HTMLResponse("<h2>Record not found</h2>", status_code=404)

        cur.execute(
            "SELECT entity_type, value FROM entities WHERE record_id = %s ORDER BY entity_type, value",
            (record_id,),
        )
        entities = cur.fetchall()

    raw_json = json.dumps(record["raw"], indent=2, default=str) if record["raw"] else "{}"

    return templates.TemplateResponse("record_detail.html", _ctx(
        request, user, "records", case_id=case_id,
        record=record, entities=entities, raw_json=raw_json,
    ))


# ── Tasks ───────────────────────────────────────────

@router.get("/cases/{case_id}/tasks", response_class=HTMLResponse)
async def tasks_list(request: Request, case_id: str):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            """SELECT t.id, t.title, t.description, t.status, t.created_at::text AS created_at,
                      (SELECT count(*) FROM worklog_steps w WHERE w.task_id = t.id) AS step_count
               FROM tasks t
               WHERE t.case_id = %s
               ORDER BY t.created_at DESC""",
            (case_id,),
        )
        tasks = cur.fetchall()

    return templates.TemplateResponse("tasks.html", _ctx(
        request, user, "tasks", case_id=case_id, tasks=tasks,
    ))


@router.get("/cases/{case_id}/tasks/new", response_class=HTMLResponse)
async def task_new_form(request: Request, case_id: str):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)
    return templates.TemplateResponse("task_new.html", _ctx(request, user, "tasks", case_id=case_id))


@router.post("/cases/{case_id}/tasks/new")
async def task_new_submit(
    request: Request, case_id: str,
    question: str = Form(...), max_steps: int = Form(15),
):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            "INSERT INTO tasks (case_id, title, description, status) VALUES (%s, %s, %s, 'pending') RETURNING id",
            (case_id, question, f"max_steps={max_steps}"),
        )
        task_id = cur.fetchone()["id"]
        cur.connection.commit()

    # Kick off RLM loop in background (if configured)
    try:
        from sphinx.core.rlm_loop import run_task_async
        run_task_async(request.app.state.settings, case_id, task_id)
    except Exception as e:
        log.warning("Could not start RLM loop: %s", e)

    return RedirectResponse(url=f"/ui/cases/{case_id}/tasks/{task_id}", status_code=303)


@router.get("/cases/{case_id}/tasks/{task_id}", response_class=HTMLResponse)
async def task_detail(request: Request, case_id: str, task_id: str):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            "SELECT id, title, description, status, created_at::text AS created_at FROM tasks WHERE id = %s AND case_id = %s",
            (task_id, case_id),
        )
        task = cur.fetchone()
        if not task:
            return HTMLResponse("<h2>Task not found</h2>", status_code=404)

        cur.execute(
            """SELECT step_number, intent, code, stdout, stderr, error,
                      round(elapsed_s * 1000)::int AS elapsed_ms
               FROM worklog_steps
               WHERE task_id = %s
               ORDER BY step_number""",
            (task_id,),
        )
        steps = cur.fetchall()

    return templates.TemplateResponse("task_detail.html", _ctx(
        request, user, "tasks", case_id=case_id,
        task=task, steps=steps,
    ))


# ── Findings ────────────────────────────────────────

@router.get("/cases/{case_id}/findings", response_class=HTMLResponse)
async def findings_list(request: Request, case_id: str):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            """SELECT id, title, body AS summary, severity,
                      evidence_ids, mitre_ids,
                      created_at::text AS created_at
               FROM findings
               WHERE case_id = %s
               ORDER BY created_at DESC""",
            (case_id,),
        )
        findings = cur.fetchall()

    return templates.TemplateResponse("findings.html", _ctx(
        request, user, "findings", case_id=case_id, findings=findings,
    ))


# ── Ingest ──────────────────────────────────────────

@router.get("/cases/{case_id}/ingest", response_class=HTMLResponse)
async def ingest_page(request: Request, case_id: str, message: str = "", error: str = ""):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    registry = get_registry()
    handlers = sorted(registry.ingest_handlers.keys())

    return templates.TemplateResponse("ingest.html", _ctx(
        request, user, "ingest", case_id=case_id,
        handlers=handlers, message=message, error=error,
    ))


@router.post("/cases/{case_id}/ingest")
async def ingest_submit(
    request: Request, case_id: str,
    record_type: str = Form(...),
    file: UploadFile = File(...),
):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    registry = get_registry()
    handler = registry.ingest_handlers.get(record_type)
    if not handler:
        return RedirectResponse(
            url=f"/ui/cases/{case_id}/ingest?error=Unknown+handler:+{record_type}",
            status_code=303,
        )

    try:
        content = await file.read()
        text = content.decode("utf-8")

        # Support JSON array or JSONL
        text = text.strip()
        if text.startswith("["):
            records = json.loads(text)
        else:
            records = [json.loads(line) for line in text.splitlines() if line.strip()]

        if not records:
            return RedirectResponse(
                url=f"/ui/cases/{case_id}/ingest?error=No+records+found+in+file",
                status_code=303,
            )

        inserted = handler(case_id, records)
        return RedirectResponse(
            url=f"/ui/cases/{case_id}/ingest?message=Ingested+{inserted}+{record_type}+records",
            status_code=303,
        )
    except json.JSONDecodeError as e:
        return RedirectResponse(
            url=f"/ui/cases/{case_id}/ingest?error=Invalid+JSON:+{e}",
            status_code=303,
        )
    except Exception as e:
        log.error("Ingest failed: %s", e)
        return RedirectResponse(
            url=f"/ui/cases/{case_id}/ingest?error=Ingest+failed:+{e}",
            status_code=303,
        )