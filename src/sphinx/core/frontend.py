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

            # Background jobs
            bg_jobs = []
            try:
                cur.execute(
                    """SELECT id, job_type, status, input_name,
                              created_at::text AS created_at,
                              updated_at::text AS updated_at,
                              summary
                       FROM background_jobs
                       WHERE case_id = %s
                       ORDER BY created_at DESC
                       LIMIT 10""",
                    (case_id,),
                )
                bg_jobs = cur.fetchall()
            except Exception:
                pass  # table may not exist yet

            summary = {
                "record_counts": record_counts,
                "tasks_total": tasks_total,
                "tasks_done": tasks_done,
                "findings_count": findings_count,
                "entity_count": entity_count,
                "total_records": total_records,
                "background_jobs": bg_jobs,
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


@router.post("/cases/{case_id}/ingest/pcap")
async def ingest_pcap_submit(
    request: Request, case_id: str,
    file: UploadFile = File(...),
):
    """Handle PCAP file upload — saves file, launches background conversion."""
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    import uuid as uuid_mod
    import threading

    # Validate file extension
    fname = file.filename or "upload.pcap"
    suffix = Path(fname).suffix.lower()
    if suffix not in (".pcap", ".pcapng", ".cap"):
        return RedirectResponse(
            url=f"/ui/cases/{case_id}/ingest?error=Invalid+file+type:+{suffix}+(expected+.pcap/.pcapng/.cap)",
            status_code=303,
        )

    # Save uploaded file
    upload_dir = Path("/app/data/pcap_uploads") / case_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    upload_id = str(uuid_mod.uuid4())[:8]
    pcap_path = upload_dir / f"{upload_id}_{fname}"

    content = await file.read()
    pcap_path.write_bytes(content)
    log.info("PCAP uploaded: %s (%d bytes)", pcap_path, len(content))

    # Create background job record
    job_id = None
    try:
        with get_cursor() as cur:
            cur.execute(
                """INSERT INTO background_jobs (case_id, job_type, status, input_name, summary)
                   VALUES (%s, 'pcap_ingest', 'running', %s, '{}')
                   RETURNING id""",
                (case_id, fname),
            )
            job_id = cur.fetchone()["id"]
            cur.connection.commit()
    except Exception as e:
        log.warning("Could not create job record (table may not exist yet): %s", e)

    # Launch background conversion via REPL
    _job_id = job_id

    def _run_pcap_convert():
        result = None
        try:
            from sphinx.core.repl_client import ReplClient
            client = ReplClient()
            if not client.connect():
                log.error("PCAP convert: cannot connect to REPL server")
                _update_job(_job_id, "failed", {"error": "Cannot connect to REPL server"})
                return
            try:
                result = client.pcap_convert(case_id, str(pcap_path))
                log.info("PCAP convert result: %s", result)
                # Clean up PCAP on success
                if result.get("status") in ("ok", "partial"):
                    pcap_path.unlink(missing_ok=True)
                _update_job(_job_id, result.get("status", "done"), result)
            finally:
                client.close()
        except Exception as e:
            log.error("PCAP convert background task failed: %s", e)
            _update_job(_job_id, "failed", {"error": str(e)})

    thread = threading.Thread(target=_run_pcap_convert, daemon=True)
    thread.start()

    return RedirectResponse(
        url=f"/ui/cases/{case_id}/ingest?message=PCAP+uploaded+({fname}).+Conversion+running+in+background+(tshark,+Suricata,+Zeek).",
        status_code=303,
    )


def _update_job(job_id: int | None, status: str, summary: dict):
    """Update a background job record."""
    if not job_id:
        return
    try:
        with get_cursor() as cur:
            from psycopg.types.json import Jsonb
            cur.execute(
                "UPDATE background_jobs SET status = %s, summary = %s, updated_at = now() WHERE id = %s",
                (status, Jsonb(summary), job_id),
            )
            cur.connection.commit()
    except Exception as e:
        log.warning("Could not update job %s: %s", job_id, e)


# ── Entities ────────────────────────────────────────

@router.get("/cases/{case_id}/entities", response_class=HTMLResponse)
async def entities_search(
    request: Request, case_id: str,
    q: str = "", entity_type: str = "", offset: int = 0,
):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    limit = 50
    with get_cursor() as cur:
        # Available entity types
        cur.execute(
            "SELECT DISTINCT entity_type FROM entities WHERE case_id = %s ORDER BY entity_type",
            (case_id,),
        )
        entity_types = [r["entity_type"] for r in cur.fetchall()]

        # Type summary (shown on default page)
        cur.execute(
            """SELECT entity_type,
                      count(DISTINCT value) AS unique_count,
                      count(*) AS total_refs
               FROM entities WHERE case_id = %s
               GROUP BY entity_type ORDER BY total_refs DESC""",
            (case_id,),
        )
        type_summary = cur.fetchall()

        # Build query
        where = "e.case_id = %s"
        params: list = [case_id]
        if q:
            where += " AND e.value ILIKE %s"
            params.append(f"%{q}%")
        if entity_type:
            where += " AND e.entity_type = %s"
            params.append(entity_type)

        # Count
        cur.execute(
            f"""SELECT count(DISTINCT (e.entity_type, e.value)) AS n
                FROM entities e WHERE {where}""",
            params,
        )
        total = cur.fetchone()["n"]

        # Results (grouped by value)
        cur.execute(
            f"""SELECT e.entity_type, e.value, count(*) AS ref_count
                FROM entities e WHERE {where}
                GROUP BY e.entity_type, e.value
                ORDER BY ref_count DESC
                LIMIT %s OFFSET %s""",
            params + [limit, offset],
        )
        entities = cur.fetchall()

    return templates.TemplateResponse("entities.html", _ctx(
        request, user, "entities", case_id=case_id,
        entities=entities, entity_types=entity_types, type_summary=type_summary,
        q=q, entity_type=entity_type, total=total, offset=offset, limit=limit,
    ))


@router.get("/cases/{case_id}/entities/pivot", response_class=HTMLResponse)
async def entity_pivot(
    request: Request, case_id: str,
    value: str = "", type: str = "",
):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        # Records containing this entity
        cur.execute(
            """SELECT DISTINCT r.id, r.record_type, r.ts::text AS ts
               FROM entities e
               JOIN records r ON r.id = e.record_id
               WHERE e.case_id = %s AND e.value = %s AND e.entity_type = %s
               ORDER BY r.ts DESC NULLS LAST""",
            (case_id, value, type),
        )
        records = cur.fetchall()

        # Record types
        record_types = sorted({r["record_type"] for r in records})

        # Co-occurring entities (other entities in the same records)
        record_ids = [r["id"] for r in records]
        related_entities = []
        if record_ids:
            cur.execute(
                """SELECT entity_type, value, count(*) AS shared_count
                   FROM entities
                   WHERE record_id = ANY(%s)
                     AND NOT (entity_type = %s AND value = %s)
                   GROUP BY entity_type, value
                   ORDER BY shared_count DESC
                   LIMIT 50""",
                (record_ids, type, value),
            )
            related_entities = cur.fetchall()

    return templates.TemplateResponse("entity_pivot.html", _ctx(
        request, user, "entities", case_id=case_id,
        value=value, entity_type=type,
        records=records, record_types=record_types,
        related_entities=related_entities,
    ))


# ── Analytics ───────────────────────────────────────

@router.get("/cases/{case_id}/analytics", response_class=HTMLResponse)
async def analytics_page(request: Request, case_id: str):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute("SELECT analytics_enabled FROM cases WHERE id = %s", (case_id,))
        row = cur.fetchone()
        analytics_enabled = row["analytics_enabled"] if row else True

    return templates.TemplateResponse("analytics.html", _ctx(
        request, user, "analytics", case_id=case_id,
        analytics_enabled=analytics_enabled,
    ))


@router.post("/cases/{case_id}/analytics/toggle")
async def analytics_toggle(request: Request, case_id: str):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            "UPDATE cases SET analytics_enabled = NOT analytics_enabled WHERE id = %s RETURNING analytics_enabled",
            (case_id,),
        )
        cur.connection.commit()

    return RedirectResponse(url=f"/ui/cases/{case_id}/analytics", status_code=303)


# ── Case Notes ──────────────────────────────────────

@router.get("/cases/{case_id}/notes", response_class=HTMLResponse)
async def notes_list(request: Request, case_id: str):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        # Ensure table exists (migration may not have run yet)
        cur.execute(
            """SELECT EXISTS (
                   SELECT FROM information_schema.tables
                   WHERE table_name = 'case_notes'
               ) AS exists"""
        )
        if not cur.fetchone()["exists"]:
            # Auto-create if missing
            cur.execute(
                """CREATE TABLE IF NOT EXISTS case_notes (
                       id SERIAL PRIMARY KEY,
                       case_id TEXT NOT NULL REFERENCES cases(id),
                       author_id TEXT REFERENCES users(id),
                       content TEXT NOT NULL DEFAULT '',
                       created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                       updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                   )"""
            )
            cur.connection.commit()

        cur.execute(
            """SELECT n.id, n.content, n.created_at::text AS created_at,
                      u.username AS author
               FROM case_notes n
               LEFT JOIN users u ON u.id = n.author_id
               WHERE n.case_id = %s
               ORDER BY n.created_at DESC""",
            (case_id,),
        )
        notes = cur.fetchall()

    return templates.TemplateResponse("notes.html", _ctx(
        request, user, "notes", case_id=case_id, notes=notes,
    ))


@router.post("/cases/{case_id}/notes")
async def note_create(request: Request, case_id: str, content: str = Form(...)):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            "INSERT INTO case_notes (case_id, author_id, content) VALUES (%s, %s, %s)",
            (case_id, user.get("sub"), content),
        )
        cur.connection.commit()

    return RedirectResponse(url=f"/ui/cases/{case_id}/notes", status_code=303)


@router.post("/cases/{case_id}/notes/{note_id}/delete")
async def note_delete(request: Request, case_id: str, note_id: int):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            "DELETE FROM case_notes WHERE id = %s AND case_id = %s",
            (note_id, case_id),
        )
        cur.connection.commit()

    return RedirectResponse(url=f"/ui/cases/{case_id}/notes", status_code=303)


# ── Report ──────────────────────────────────────────

@router.get("/cases/{case_id}/report", response_class=HTMLResponse)
async def report_page(request: Request, case_id: str):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    try:
        from sphinx.core.report import generate_report
        settings = request.app.state.settings
        report = generate_report(settings, case_id)
        return templates.TemplateResponse("report.html", _ctx(
            request, user, "report", case_id=case_id, report=report, error=None,
        ))
    except Exception as e:
        log.error("Report generation failed: %s", e)
        return templates.TemplateResponse("report.html", _ctx(
            request, user, "report", case_id=case_id,
            report=None, error=f"Report generation failed: {e}",
        ))


@router.get("/cases/{case_id}/report/download")
async def report_download(request: Request, case_id: str):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    from fastapi.responses import JSONResponse
    from sphinx.core.report import generate_report
    settings = request.app.state.settings
    report = generate_report(settings, case_id)
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f"attachment; filename=sphinx-report-{case_id[:8]}.json"},
    )


# ── Admin: User Management ───────────────────────────

def _require_admin(request: Request):
    """Return user dict if admin, else redirect."""
    user = _get_user(request)
    if not user or user.get("role") != "admin":
        return None
    return user


@router.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page(request: Request, success: str = "", error: str = ""):
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute("""
            SELECT u.*, count(ca.case_id) AS case_count
            FROM users u
            LEFT JOIN case_assignments ca ON ca.user_id = u.id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        """)
        users = [
            {**row, "created_at": str(row["created_at"]) if row["created_at"] else None}
            for row in cur.fetchall()
        ]

    return templates.TemplateResponse("admin_users.html", _ctx(
        request, user, "admin_users", users=users, success=success, error=error,
    ))


@router.post("/admin/users")
async def admin_create_user(
    request: Request, username: str = Form(...), password: str = Form(...), role: str = Form("analyst"),
):
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    if len(password) < 8:
        return RedirectResponse(url="/ui/admin/users?error=Password+must+be+at+least+8+characters", status_code=303)

    from sphinx.core.auth import hash_password
    import uuid
    user_id = str(uuid.uuid4())
    pw_hash = hash_password(password)

    try:
        with get_cursor() as cur:
            cur.execute(
                "INSERT INTO users (id, username, password_hash, role) VALUES (%s, %s, %s, %s)",
                (user_id, username, pw_hash, role),
            )
            cur.connection.commit()
        return RedirectResponse(url=f"/ui/admin/users?success=User+'{username}'+created", status_code=303)
    except Exception:
        return RedirectResponse(url=f"/ui/admin/users?error=Username+'{username}'+already+exists", status_code=303)


@router.post("/admin/users/{user_id}/toggle")
async def admin_toggle_user(request: Request, user_id: str):
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            "UPDATE users SET active = NOT active WHERE id = %s AND role != 'admin' RETURNING active",
            (user_id,),
        )
        row = cur.fetchone()
        cur.connection.commit()

    status_text = "activated" if row and row["active"] else "deactivated"
    return RedirectResponse(url=f"/ui/admin/users?success=User+{status_text}", status_code=303)


@router.get("/admin/users/{user_id}", response_class=HTMLResponse)
async def admin_user_detail(request: Request, user_id: str, success: str = "", error: str = ""):
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        target_user = cur.fetchone()
        if not target_user:
            return RedirectResponse(url="/ui/admin/users?error=User+not+found", status_code=303)
        target_user = {**target_user, "created_at": str(target_user["created_at"]) if target_user["created_at"] else None}

        # Case assignments
        cur.execute("""
            SELECT ca.*, c.name AS case_name
            FROM case_assignments ca
            JOIN cases c ON c.id = ca.case_id
            WHERE ca.user_id = %s
            ORDER BY ca.assigned_at
        """, (user_id,))
        assignments = [
            {**row, "assigned_at": str(row["assigned_at"]) if row["assigned_at"] else None}
            for row in cur.fetchall()
        ]

        # Available cases (not already assigned)
        assigned_ids = [a["case_id"] for a in assignments]
        cur.execute("SELECT id, name FROM cases ORDER BY name")
        all_cases = cur.fetchall()
        available_cases = [c for c in all_cases if c["id"] not in assigned_ids]

    return templates.TemplateResponse("admin_user_detail.html", _ctx(
        request, user, "admin_users",
        target_user=target_user, assignments=assignments,
        available_cases=available_cases, success=success, error=error,
    ))


@router.post("/admin/users/{user_id}/role")
async def admin_change_role(request: Request, user_id: str, role: str = Form(...)):
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute("UPDATE users SET role = %s WHERE id = %s", (role, user_id))
        cur.connection.commit()

    return RedirectResponse(url=f"/ui/admin/users/{user_id}?success=Role+updated+to+{role}", status_code=303)


@router.post("/admin/users/{user_id}/password")
async def admin_reset_password(request: Request, user_id: str, password: str = Form(...)):
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    if len(password) < 8:
        return RedirectResponse(url=f"/ui/admin/users/{user_id}?error=Password+must+be+at+least+8+characters", status_code=303)

    from sphinx.core.auth import hash_password
    pw_hash = hash_password(password)
    with get_cursor() as cur:
        cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (pw_hash, user_id))
        cur.connection.commit()

    return RedirectResponse(url=f"/ui/admin/users/{user_id}?success=Password+reset", status_code=303)


@router.post("/admin/users/{user_id}/assign")
async def admin_assign_case(request: Request, user_id: str, case_id: str = Form(...)):
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    try:
        with get_cursor() as cur:
            cur.execute(
                "INSERT INTO case_assignments (user_id, case_id) VALUES (%s, %s)",
                (user_id, case_id),
            )
            cur.connection.commit()
        return RedirectResponse(url=f"/ui/admin/users/{user_id}?success=Case+assigned", status_code=303)
    except Exception:
        return RedirectResponse(url=f"/ui/admin/users/{user_id}?error=Already+assigned", status_code=303)


@router.post("/admin/users/{user_id}/unassign")
async def admin_unassign_case(request: Request, user_id: str, case_id: str = Form(...)):
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            "DELETE FROM case_assignments WHERE user_id = %s AND case_id = %s",
            (user_id, case_id),
        )
        cur.connection.commit()

    return RedirectResponse(url=f"/ui/admin/users/{user_id}?success=Case+unassigned", status_code=303)