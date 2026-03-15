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

# ── In-memory job tracking (replaces unreliable DB-mediated progress) ──
import time as _time
import threading as _threading

_LIVE_JOBS: dict[int, dict] = {}  # job_id -> live state dict
_LIVE_JOBS_LOCK = _threading.Lock()

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
        "mode": user.get("mode", "investigator") if user else "investigator",
        "correlation_case_id": user.get("correlation_case_id", "") if user else "",
        "source_case_ids": user.get("source_case_ids", []) if user else [],
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
async def dashboard(request: Request, case_id: str = "", mode: str = ""):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    # Mode switch — re-issue JWT with new mode
    current_mode = user.get("mode", "investigator")
    if mode and mode in ("investigator", "correlator") and mode != current_mode:
        from sphinx.core.auth import create_token
        settings = request.app.state.settings
        new_token = create_token(
            settings,
            user_id=user["sub"],
            role=user["role"],
            case_ids=user.get("case_ids", []),
            mode=mode,
            correlation_case_id=user.get("correlation_case_id", ""),
            source_case_ids=user.get("source_case_ids", []),
        )
        url = f"/ui/?case_id={case_id}" if case_id else "/ui/"
        response = RedirectResponse(url=url, status_code=303)
        response.set_cookie("sphinx_token", new_token, httponly=True, max_age=86400)
        return response

    with get_cursor() as cur:
        # List cases (include case_type for correlator filtering)
        cur.execute("""
            SELECT id, name, status, created_at::text AS created_at,
                   COALESCE(case_type, 'investigation') AS case_type
            FROM cases ORDER BY created_at DESC
        """)
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
                # Mark stale running jobs as failed before fetching.
                # Use LEAST(created_at, updated_at) so it works even if
                # progress was never written (updated_at = created_at).
                cur.execute(
                    """UPDATE background_jobs
                       SET status = 'failed',
                           summary = COALESCE(summary, '{}'::jsonb)
                                     || '{"error": "Timed out (no response after 15 min)"}'::jsonb,
                           updated_at = now()
                       WHERE case_id = %s AND status = 'running'
                         AND LEAST(created_at, updated_at) < now() - interval '15 minutes'""",
                    (case_id,),
                )
                cur.connection.commit()
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

    # Correlator summary (when in correlator mode with cases selected)
    correlator_summary = []
    src_ids = user.get("source_case_ids", [])
    if current_mode == "correlator" and src_ids:
        with get_cursor() as cur:
            cur.execute(
                """SELECT c.id, c.name, count(r.id) AS record_count
                   FROM cases c
                   LEFT JOIN records r ON r.case_id = c.id
                   WHERE c.id = ANY(%s)
                   GROUP BY c.id ORDER BY c.name""",
                (src_ids,),
            )
            correlator_summary = cur.fetchall()

    return templates.TemplateResponse("dashboard.html", _ctx(
        request, user, "dashboard", case_id=case_id,
        cases=cases, summary=summary, correlator_summary=correlator_summary,
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
        task_mode = user.get("mode", "investigator")
        task_source = user.get("source_case_ids", [])
        run_task_async(request.app.state.settings, case_id, task_id,
                       mode=task_mode, source_case_ids=task_source)
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

    # Save uploaded file to shared volume (accessible by both API + REPL).
    # uvicorn --reload-dir /app/src ensures data writes don't trigger reloads.
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

    # Launch background conversion via REPL with in-memory progress tracking
    _job_id = job_id

    def _poll_record_counts(job_id: int, case_id: str, stop_event: threading.Event):
        """Poll DB for record counts while REPL converts, update in-memory state."""
        import time
        while not stop_event.is_set():
            time.sleep(2)
            try:
                with get_cursor() as cur:
                    cur.execute(
                        """SELECT record_type, count(*) AS n
                           FROM records WHERE case_id = %s
                             AND source_plugin = 'sphinx-plugin-pcap'
                           GROUP BY record_type""",
                        (case_id,),
                    )
                    rows = cur.fetchall()
                counts = {r["record_type"]: r["n"] for r in rows}
                total = sum(counts.values())
                with _LIVE_JOBS_LOCK:
                    state = _LIVE_JOBS.get(job_id)
                    if state and state["status"] == "running":
                        state["total_inserted"] = total
                        state["record_counts"] = counts
                        state["elapsed_s"] = round(time.time() - state["_start"], 1)
                        # Estimate progress from record types seen
                        stages_seen = set(counts.keys())
                        if any(k.startswith("tshark") for k in stages_seen):
                            state["stage"] = "ingesting tshark streams"
                            state["pct"] = min(90, 50 + total // 5)
                        elif any(k.startswith("zeek") for k in stages_seen):
                            state["stage"] = "ingesting Zeek records"
                            state["pct"] = min(60, 30 + total // 5)
                        elif any(k.startswith("suricata") for k in stages_seen):
                            state["stage"] = "ingesting Suricata records"
                            state["pct"] = min(30, 10 + total // 5)
                        elif total > 0:
                            state["stage"] = "ingesting records"
                            state["pct"] = min(20, total // 5)
                        log.debug("Job %s progress: %s records, stage=%s", job_id, total, state.get("stage"))
            except Exception as e:
                log.debug("Progress poll error (non-fatal): %s", e)

    def _run_pcap_convert():
        import time
        # Initialize in-memory state
        with _LIVE_JOBS_LOCK:
            _LIVE_JOBS[_job_id] = {
                "status": "running",
                "stage": "starting conversion",
                "pct": 0,
                "total_inserted": 0,
                "record_counts": {},
                "errors": [],
                "elapsed_s": 0,
                "_start": time.time(),
            }

        stop_poll = threading.Event()
        poll_thread = threading.Thread(
            target=_poll_record_counts, args=(_job_id, case_id, stop_poll), daemon=True,
        )
        poll_thread.start()

        result = None
        try:
            from sphinx.core.repl_client import ReplClient
            client = ReplClient()
            if not client.connect():
                log.error("PCAP convert: cannot connect to REPL server")
                with _LIVE_JOBS_LOCK:
                    _LIVE_JOBS[_job_id].update(status="failed", stage="connection failed",
                                                errors=["Cannot connect to REPL server"])
                _update_job(_job_id, "failed", {"error": "Cannot connect to REPL server"})
                return
            with _LIVE_JOBS_LOCK:
                _LIVE_JOBS[_job_id]["stage"] = "connected to REPL"
                _LIVE_JOBS[_job_id]["pct"] = 5

            try:
                result = client.pcap_convert(case_id, str(pcap_path), job_id=_job_id)
                log.info("PCAP convert result: %s", result)
                elapsed = round(time.time() - _LIVE_JOBS[_job_id]["_start"], 1)

                # Build final summary from result + polled counts
                final_status = result.get("status", "done")
                with _LIVE_JOBS_LOCK:
                    state = _LIVE_JOBS[_job_id]
                    state["status"] = final_status
                    state["pct"] = 100
                    state["stage"] = "complete"
                    state["elapsed_s"] = elapsed
                    if result.get("total_inserted"):
                        state["total_inserted"] = result["total_inserted"]
                    if result.get("record_counts"):
                        state["record_counts"] = result["record_counts"]
                    if result.get("errors"):
                        state["errors"] = result["errors"]
                    summary = {k: v for k, v in state.items() if not k.startswith("_")}

                # Clean up PCAP on success
                if final_status in ("ok", "partial"):
                    pcap_path.unlink(missing_ok=True)
                _update_job(_job_id, final_status, summary)
            finally:
                client.close()
        except Exception as e:
            log.error("PCAP convert background task failed: %s", e)
            with _LIVE_JOBS_LOCK:
                state = _LIVE_JOBS.get(_job_id, {})
                state["status"] = "failed"
                state["stage"] = "error"
                state["errors"] = [str(e)]
            _update_job(_job_id, "failed", {"error": str(e)})
        finally:
            stop_poll.set()

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


@router.get("/cases/{case_id}/jobs/{job_id}/status")
async def job_status_json(request: Request, case_id: str, job_id: int):
    """Return current job status as JSON (polled by the dashboard JS).

    Reads from in-memory _LIVE_JOBS first (updated by the background thread
    without any DB round-trip). Falls back to DB for completed/historical jobs.
    """
    import json as _json

    # In-memory state — always fresh, no DB needed
    with _LIVE_JOBS_LOCK:
        live = _LIVE_JOBS.get(job_id)
        if live:
            data = {
                "status": live["status"],
                "pct": live.get("pct", 0),
                "stage": live.get("stage", ""),
                "total_inserted": live.get("total_inserted", 0),
                "record_counts": live.get("record_counts", {}),
                "errors": live.get("errors", []),
                "elapsed_s": live.get("elapsed_s", 0),
            }
            return HTMLResponse(_json.dumps(data), media_type="application/json")

    # Fallback to DB for historical/completed jobs
    try:
        with get_cursor() as cur:
            cur.execute(
                "SELECT status, summary FROM background_jobs WHERE id = %s AND case_id = %s",
                (job_id, case_id),
            )
            row = cur.fetchone()
    except Exception:
        row = None

    if not row:
        return HTMLResponse('{"error":"not found"}', status_code=404,
                            media_type="application/json")

    summary = row["summary"] or {}
    data = {
        "status": row["status"],
        "pct": summary.get("pct", 0),
        "stage": summary.get("stage", ""),
        "total_inserted": summary.get("total_inserted", 0),
        "record_counts": summary.get("record_counts", {}),
        "errors": summary.get("errors", []),
        "elapsed_s": summary.get("elapsed_s", 0),
    }
    return HTMLResponse(_json.dumps(data), media_type="application/json")


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


# ── Correlator Mode ────────────────────────────────

@router.post("/correlator/configure")
async def correlator_configure(request: Request):
    """Apply correlator configuration — selected source cases and correlation case."""
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    form = await request.form()
    source_case_ids = form.getlist("source_case_ids")
    correlation_case_id = form.get("correlation_case_id", "")

    from sphinx.core.auth import create_token
    settings = request.app.state.settings
    new_token = create_token(
        settings,
        user_id=user["sub"],
        role=user["role"],
        case_ids=user.get("case_ids", []),
        mode="correlator",
        correlation_case_id=correlation_case_id,
        source_case_ids=source_case_ids,
    )
    response = RedirectResponse(url="/ui/", status_code=303)
    response.set_cookie("sphinx_token", new_token, httponly=True, max_age=86400)
    return response


@router.get("/correlator/new-case", response_class=HTMLResponse)
async def correlator_new_case_form(request: Request):
    """Form to create a new correlation case."""
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    source_case_ids = user.get("source_case_ids", [])
    with get_cursor() as cur:
        if source_case_ids:
            cur.execute(
                "SELECT id, name FROM cases WHERE id = ANY(%s) ORDER BY name",
                (source_case_ids,),
            )
            source_cases = cur.fetchall()
        else:
            source_cases = []

    return templates.TemplateResponse("correlator_new_case.html", _ctx(
        request, user, "dashboard", source_cases=source_cases,
    ))


@router.post("/correlator/new-case")
async def correlator_new_case_submit(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
):
    """Create a correlation case and activate correlator mode."""
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    import uuid
    case_id = str(uuid.uuid4())
    source_case_ids = user.get("source_case_ids", [])

    with get_cursor() as cur:
        cur.execute(
            """INSERT INTO cases (id, name, description, status, case_type, source_case_ids)
               VALUES (%s, %s, %s, 'open', 'correlation', %s)""",
            (case_id, name, description, source_case_ids),
        )
        cur.connection.commit()

    # Re-issue JWT with the new correlation case
    from sphinx.core.auth import create_token
    settings = request.app.state.settings
    new_token = create_token(
        settings,
        user_id=user["sub"],
        role=user["role"],
        case_ids=user.get("case_ids", []),
        mode="correlator",
        correlation_case_id=case_id,
        source_case_ids=source_case_ids,
    )
    response = RedirectResponse(url="/ui/", status_code=303)
    response.set_cookie("sphinx_token", new_token, httponly=True, max_age=86400)
    return response


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


# ── Admin: Data Management ─────────────────────────

def _delete_case_evidence(cur, case_id: str) -> dict:
    """Delete all evidence for a case (records, entities, precomputed, etc).

    Respects FK ordering. Returns counts of deleted rows per table.
    """
    counts = {}

    # Entities reference records, so delete first
    cur.execute("DELETE FROM entities WHERE case_id = %s", (case_id,))
    counts["entities"] = cur.rowcount

    # Scratch precomputed references both tasks and cases
    cur.execute("DELETE FROM scratch_precomputed WHERE case_id = %s", (case_id,))
    counts["scratch_precomputed"] = cur.rowcount

    # Records (the main evidence)
    cur.execute("DELETE FROM records WHERE case_id = %s", (case_id,))
    counts["records"] = cur.rowcount

    # Findings reference cases (evidence_ids are just an int array, not FK)
    cur.execute("DELETE FROM findings WHERE case_id = %s", (case_id,))
    counts["findings"] = cur.rowcount

    return counts


def _delete_case_tasks(cur, case_id: str) -> dict:
    """Delete tasks and worklog for a case. Returns counts."""
    counts = {}

    # Worklog steps reference tasks
    cur.execute(
        "DELETE FROM worklog_steps WHERE task_id IN (SELECT id FROM tasks WHERE case_id = %s)",
        (case_id,),
    )
    counts["worklog_steps"] = cur.rowcount

    cur.execute("DELETE FROM tasks WHERE case_id = %s", (case_id,))
    counts["tasks"] = cur.rowcount

    return counts


def _delete_case_all(cur, case_id: str) -> dict:
    """Delete a case and everything tied to it. Returns counts."""
    counts = {}

    # Evidence + derived data
    counts.update(_delete_case_evidence(cur, case_id))

    # Tasks + worklog
    counts.update(_delete_case_tasks(cur, case_id))

    # Notes
    cur.execute("DELETE FROM case_notes WHERE case_id = %s", (case_id,))
    counts["case_notes"] = cur.rowcount

    # Background jobs
    cur.execute("DELETE FROM background_jobs WHERE case_id = %s", (case_id,))
    counts["background_jobs"] = cur.rowcount

    # Case assignments
    cur.execute("DELETE FROM case_assignments WHERE case_id = %s", (case_id,))
    counts["case_assignments"] = cur.rowcount

    # The case itself
    cur.execute("DELETE FROM cases WHERE id = %s", (case_id,))
    counts["cases"] = cur.rowcount

    return counts


@router.get("/admin/data", response_class=HTMLResponse)
async def admin_data_page(request: Request, success: str = "", error: str = ""):
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        # All cases with record counts
        cur.execute("""
            SELECT c.id, c.name, c.status,
                   count(r.id) AS record_count
            FROM cases c
            LEFT JOIN records r ON r.case_id = c.id
            GROUP BY c.id ORDER BY c.created_at DESC
        """)
        cases = cur.fetchall()

        # Background jobs with ingest types + linked record counts
        cur.execute("""
            SELECT j.id, j.case_id, j.job_type, j.status, j.input_name,
                   j.created_at::text AS created_at,
                   c.name AS case_name,
                   count(r.id) AS record_count
            FROM background_jobs j
            JOIN cases c ON c.id = j.case_id
            LEFT JOIN records r ON r.job_id = j.id
            WHERE j.job_type LIKE '%ingest%'
            GROUP BY j.id, c.name
            ORDER BY j.created_at DESC
            LIMIT 50
        """)
        jobs = cur.fetchall()

    return templates.TemplateResponse("admin_data.html", _ctx(
        request, user, "admin_data",
        cases=cases, jobs=jobs, success=success, error=error,
    ))


@router.post("/admin/data/delete-job-records")
async def admin_delete_job_records(request: Request, job_id: int = Form(...)):
    """Delete all records linked to a specific ingest job."""
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        # Get job info for message
        cur.execute("SELECT id, job_type, input_name, case_id FROM background_jobs WHERE id = %s", (job_id,))
        job = cur.fetchone()
        if not job:
            return RedirectResponse(url="/ui/admin/data?error=Job+not+found", status_code=303)

        # Delete entities that reference these records
        cur.execute(
            "DELETE FROM entities WHERE record_id IN (SELECT id FROM records WHERE job_id = %s)",
            (job_id,),
        )
        entities_deleted = cur.rowcount

        # Delete the records
        cur.execute("DELETE FROM records WHERE job_id = %s", (job_id,))
        records_deleted = cur.rowcount

        # Update job status to reflect deletion
        from psycopg.types.json import Jsonb
        cur.execute(
            "UPDATE background_jobs SET status = 'deleted', summary = summary || %s, updated_at = now() WHERE id = %s",
            (Jsonb({"deleted_records": records_deleted, "deleted_entities": entities_deleted}), job_id),
        )
        cur.connection.commit()

    msg = f"Deleted {records_deleted} records and {entities_deleted} entities from job #{job_id} ({job['input_name'] or job['job_type']})"
    return RedirectResponse(url=f"/ui/admin/data?success={msg.replace(' ', '+')}", status_code=303)


@router.post("/admin/data/delete-case-evidence")
async def admin_delete_case_evidence(request: Request, case_id: str = Form(...)):
    """Delete all evidence for a case but keep the case itself."""
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute("SELECT name FROM cases WHERE id = %s", (case_id,))
        case = cur.fetchone()
        if not case:
            return RedirectResponse(url="/ui/admin/data?error=Case+not+found", status_code=303)

        counts = _delete_case_evidence(cur, case_id)
        counts.update(_delete_case_tasks(cur, case_id))

        # Also clear background jobs
        cur.execute("DELETE FROM background_jobs WHERE case_id = %s", (case_id,))
        counts["background_jobs"] = cur.rowcount

        cur.connection.commit()

    total = sum(counts.values())
    msg = f"Deleted {total} rows of evidence from case '{case['name']}' (records: {counts.get('records', 0)}, entities: {counts.get('entities', 0)}, tasks: {counts.get('tasks', 0)})"
    return RedirectResponse(url=f"/ui/admin/data?success={msg.replace(' ', '+')}", status_code=303)


@router.post("/admin/data/delete-case")
async def admin_delete_case(request: Request, case_id: str = Form(...)):
    """Delete a case and everything tied to it."""
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute("SELECT name FROM cases WHERE id = %s", (case_id,))
        case = cur.fetchone()
        if not case:
            return RedirectResponse(url="/ui/admin/data?error=Case+not+found", status_code=303)

        counts = _delete_case_all(cur, case_id)
        cur.connection.commit()

    total = sum(counts.values())
    msg = f"Deleted case '{case['name']}' and {total - 1} related rows"
    return RedirectResponse(url=f"/ui/admin/data?success={msg.replace(' ', '+')}", status_code=303)