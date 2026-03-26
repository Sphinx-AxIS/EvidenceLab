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
from sphinx.core.attack_windows_presets import ATTACK_WINDOWS_PRESETS
from sphinx.core.db import get_cursor
from sphinx.core.plugin_loader import get_registry
from sphinx.core.rule_assistant import build_rule_recommendations

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


def _fix_stale_jobs(cur, case_id: str | None = None) -> None:
    """Auto-fix stale background jobs.

    - Jobs with linked records stuck as 'running' → 'done' (after 10 min)
    - Jobs with no results stuck as 'running' → 'failed' (after 4 hours)
    """
    case_filter = "AND j.case_id = %s" if case_id else ""
    params = [case_id] if case_id else []

    # Auto-fix jobs that have linked records in the DB (the actual source of truth)
    cur.execute(
        f"""UPDATE background_jobs j
            SET status = 'done', updated_at = now()
            WHERE j.status = 'running'
              AND LEAST(j.created_at, j.updated_at) < now() - interval '10 minutes'
              {case_filter}
              AND EXISTS (SELECT 1 FROM records r WHERE r.job_id = j.id)""",
        params,
    )

    # Also fix jobs where summary says records were inserted
    cur.execute(
        f"""UPDATE background_jobs
            SET status = 'done', updated_at = now()
            WHERE status = 'running'
              AND LEAST(created_at, updated_at) < now() - interval '10 minutes'
              {"AND case_id = %s" if case_id else ""}
              AND summary->>'total_inserted' IS NOT NULL
              AND (summary->>'total_inserted')::int > 0""",
        params,
    )

    # Mark truly abandoned jobs as failed
    cur.execute(
        f"""UPDATE background_jobs j
            SET status = 'failed',
                summary = COALESCE(j.summary, '{{}}'::jsonb)
                          || '{{"error": "Abandoned (no progress after 4 hours)"}}'::jsonb,
                updated_at = now()
            WHERE j.status = 'running'
              AND LEAST(j.created_at, j.updated_at) < now() - interval '4 hours'
              {case_filter}
              AND NOT EXISTS (SELECT 1 FROM records r WHERE r.job_id = j.id)
              AND (j.summary->>'total_inserted' IS NULL
                   OR (j.summary->>'total_inserted')::int = 0)""",
        params,
    )
    cur.connection.commit()


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


def _suggest_rule_type(record_type: str) -> str:
    if record_type.startswith("win_evt_"):
        return "sigma"
    if record_type.startswith(("suricata_", "zeek_", "tshark_")):
        return "suricata"
    return ""


def _sigma_service_from_channel(channel: str) -> str:
    value = (channel or "").strip().lower()
    if value == "security":
        return "security"
    if "powershell" in value:
        return "powershell"
    if "sysmon" in value:
        return "sysmon"
    if value in ("application", "system"):
        return value
    return ""


def _build_sigma_starter(source_record: dict | None, selected_channel: str, selected_event_id: str) -> str:
    service = _sigma_service_from_channel(selected_channel)
    title_stub = "custom_windows_event_detection"
    if source_record:
        record_type = source_record.get("record_type", "")
        if record_type:
            title_stub = f"{record_type}_event_detection"

    selection_lines = []
    if selected_event_id:
        selection_lines.append(f"    EventID: {selected_event_id}")

    event_data = {}
    if source_record and isinstance(source_record.get("raw"), dict):
        event_data = source_record["raw"].get("EventData") or {}

    useful_fields = [
        "TargetUserName",
        "TargetDomainName",
        "SubjectUserName",
        "IpAddress",
        "WorkstationName",
        "Image",
        "ParentImage",
        "CommandLine",
        "ProcessId",
        "ScriptBlockText",
    ]
    for field in useful_fields:
        value = event_data.get(field)
        if isinstance(value, str) and value.strip():
            sample = value.strip().replace("\\", "\\\\").replace("'", "")
            if len(sample) > 80:
                sample = sample[:77] + "..."
            selection_lines.append(f"    EventData.{field}: '{sample}'")
        if len(selection_lines) >= 4:
            break

    if not selection_lines:
        selection_lines.append("    EventID: 4624")

    logsource_lines = ["  product: windows"]
    if service:
        logsource_lines.append(f"  service: {service}")

    return "\n".join([
        f"title: {title_stub}",
        "id: REPLACE-WITH-UUID",
        "status: experimental",
        "description: Analyst-authored Sigma rule from EvidenceLab guided builder",
        "logsource:",
        *logsource_lines,
        "detection:",
        "  selection:",
        *selection_lines,
        "  condition: selection",
        "level: medium",
        "tags:",
        "  - attack.execution",
    ])


def _record_highlights(record_type: str, raw: dict[str, Any] | None) -> list[dict[str, str]]:
    raw = raw or {}
    highlights: list[dict[str, str]] = []

    def add(label: str, value: Any) -> None:
        if value is None:
            return
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return
        highlights.append({"label": label, "value": str(value)})

    if record_type.startswith("win_evt_"):
        event_data = raw.get("EventData") if isinstance(raw.get("EventData"), dict) else {}
        add("Channel", raw.get("Channel"))
        add("EventID", raw.get("EventID"))
        add("Provider", raw.get("Provider"))
        add("Computer", raw.get("Computer"))
        for label, key in (
            ("Target User", "TargetUserName"),
            ("Subject User", "SubjectUserName"),
            ("Image", "Image"),
            ("Parent Image", "ParentImage"),
            ("Command Line", "CommandLine"),
            ("Source IP", "IpAddress"),
            ("Workstation", "WorkstationName"),
            ("Script Block", "ScriptBlockText"),
        ):
            add(label, event_data.get(key))
    else:
        for label, key in (
            ("Alert Signature", "alert_signature"),
            ("Service", "service"),
            ("Protocol", "proto"),
            ("Query", "query"),
            ("Host", "host"),
            ("URI", "uri"),
            ("Method", "method"),
            ("Source IP", "src_ip"),
            ("Destination IP", "dest_ip"),
            ("Orig Host", "id.orig_h"),
            ("Resp Host", "id.resp_h"),
        ):
            add(label, raw.get(key))

    return highlights[:10]


def _record_context_counts(case_id: str, record_type: str, raw: dict[str, Any] | None) -> list[dict[str, str]]:
    raw = raw or {}
    counts: list[dict[str, str]] = []

    with get_cursor() as cur:
        cur.execute(
            "SELECT count(*) AS n FROM records WHERE case_id = %s AND record_type = %s",
            (case_id, record_type),
        )
        counts.append({"label": f"Records of type: {record_type}", "value": str(cur.fetchone()["n"])})

        if record_type.startswith("win_evt_"):
            channel = raw.get("Channel")
            event_id = raw.get("EventID")
            if channel:
                cur.execute(
                    "SELECT count(*) AS n FROM records WHERE case_id = %s AND COALESCE(raw->>'Channel', '') = %s",
                    (case_id, str(channel)),
                )
                counts.append({"label": f"Records in channel {channel}", "value": str(cur.fetchone()["n"])})
            if event_id not in (None, ""):
                cur.execute(
                    "SELECT count(*) AS n FROM records WHERE case_id = %s AND COALESCE(raw->>'EventID', '') = %s",
                    (case_id, str(event_id)),
                )
                counts.append({"label": f"Records with EventID {event_id}", "value": str(cur.fetchone()["n"])})
            if channel and event_id not in (None, ""):
                cur.execute(
                    """SELECT count(*) AS n FROM records
                       WHERE case_id = %s
                         AND COALESCE(raw->>'Channel', '') = %s
                         AND COALESCE(raw->>'EventID', '') = %s""",
                    (case_id, str(channel), str(event_id)),
                )
                counts.append({"label": f"{channel} events with EventID {event_id}", "value": str(cur.fetchone()["n"])})

            event_data = raw.get("EventData") if isinstance(raw.get("EventData"), dict) else {}
            for label, key in (
                ("Same target user", "TargetUserName"),
                ("Same image", "Image"),
                ("Same source IP", "IpAddress"),
            ):
                value = event_data.get(key)
                if isinstance(value, str) and value.strip():
                    cur.execute(
                        f"""SELECT count(*) AS n FROM records
                            WHERE case_id = %s
                              AND COALESCE(raw->'EventData'->>'{key}', '') = %s""",
                        (case_id, value.strip()),
                    )
                    counts.append({"label": f"{label}: {value.strip()}", "value": str(cur.fetchone()["n"])})
        else:
            for label, key in (
                ("Same alert signature", "alert_signature"),
                ("Same service", "service"),
                ("Same query", "query"),
                ("Same host", "host"),
            ):
                value = raw.get(key)
                if isinstance(value, str) and value.strip():
                    cur.execute(
                        f"SELECT count(*) AS n FROM records WHERE case_id = %s AND COALESCE(raw->>'{key}', '') = %s",
                        (case_id, value.strip()),
                    )
                    counts.append({"label": f"{label}: {value.strip()}", "value": str(cur.fetchone()["n"])})

    return counts[:8]


def _record_interpretation(record_type: str, raw: dict[str, Any] | None) -> str:
    raw = raw or {}
    if record_type == "win_evt_security":
        return "Windows Security events are often useful for authentication, privilege use, and account activity detections."
    if record_type == "win_evt_sysmon":
        return "Sysmon events are often strong Sigma candidates because they capture process, network, and registry behavior with stable field names."
    if record_type == "win_evt_powershell":
        return "PowerShell events can be detection-worthy when they show script execution, encoded commands, or suspicious automation patterns."
    if record_type.startswith("win_evt_"):
        return "Windows event records should usually be evaluated by channel, EventID, and stable EventData fields before creating a Sigma rule."
    if record_type.startswith(("suricata_", "zeek_", "tshark_")):
        return "Network-derived records should be reviewed for packet-visible behavior before writing a Suricata signature."
    return "Inspect the key fields and case context to decide whether this record represents stable, repeatable behavior worth detecting."


# ── Auth pages ──────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse(request, "login.html", {"request": request, "error": error})


@router.post("/login")
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    with get_cursor() as cur:
        cur.execute(
            "SELECT id, username, role, password_hash FROM users WHERE username = %s",
            (username,),
        )
        row = cur.fetchone()

    if not row or not verify_password(password, row["password_hash"]):
        return templates.TemplateResponse(request, "login.html", {
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
        # Use a safe query that works even if case_type column hasn't been migrated yet
        try:
            cur.execute("""
                SELECT id, name, status, created_at::text AS created_at,
                       COALESCE(case_type, 'investigation') AS case_type
                FROM cases ORDER BY created_at DESC
            """)
        except Exception:
            cur.connection.rollback()
            cur.execute("""
                SELECT id, name, status, created_at::text AS created_at,
                       'investigation' AS case_type
                FROM cases ORDER BY created_at DESC
            """)
        cases = cur.fetchall()

        # Current case metadata
        case_meta = None
        if case_id:
            cur.execute(
                """SELECT id, name, description, home_net, victim_ips, status
                   FROM cases WHERE id = %s""",
                (case_id,),
            )
            case_meta = cur.fetchone()

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
                _fix_stale_jobs(cur, case_id)
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

    return templates.TemplateResponse(request, "dashboard.html", _ctx(
        request, user, "dashboard", case_id=case_id,
        cases=cases, summary=summary, correlator_summary=correlator_summary,
        case_meta=case_meta,
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

    return templates.TemplateResponse(request, "cases.html", _ctx(request, user, "cases", cases=cases))


@router.get("/cases/new", response_class=HTMLResponse)
async def case_new_form(request: Request):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)
    return templates.TemplateResponse(request, "case_new.html", _ctx(request, user, "cases"))


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


@router.post("/cases/{case_id}/settings")
async def case_settings_submit(
    request: Request, case_id: str,
    home_net: str = Form(""),
    victim_ips: str = Form(""),
    description: str = Form(""),
):
    """Save case-specific settings (HOME_NET, victim IPs, description)."""
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    # Parse comma-separated values into arrays
    home_net_list = [x.strip() for x in home_net.split(",") if x.strip()]
    victim_ips_list = [x.strip() for x in victim_ips.split(",") if x.strip()]

    with get_cursor() as cur:
        cur.execute(
            """UPDATE cases
               SET home_net = %s, victim_ips = %s, description = %s, updated_at = now()
               WHERE id = %s""",
            (home_net_list, victim_ips_list, description, case_id),
        )
        cur.connection.commit()

    return RedirectResponse(url=f"/ui/?case_id={case_id}", status_code=303)


# ── Records ─────────────────────────────────────────

@router.get("/cases/{case_id}/records", response_class=HTMLResponse)
async def records_list(
    request: Request,
    case_id: str,
    type: str = "",
    offset: int = 0,
    q: str = "",
    channel: str = "",
    event_id: str = "",
):
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

        cur.execute(
            """SELECT DISTINCT COALESCE(raw->>'Channel', '') AS channel
               FROM records
               WHERE case_id = %s
                 AND record_type LIKE 'win_evt_%%'
                 AND COALESCE(raw->>'Channel', '') != ''
               ORDER BY channel""",
            (case_id,),
        )
        win_channels = [r["channel"] for r in cur.fetchall()]

        # Query
        where = "case_id = %s AND record_type != 'worklog_step'"
        params = [case_id]
        if type:
            where += " AND record_type = %s"
            params.append(type)
        if channel:
            where += " AND COALESCE(raw->>'Channel', '') = %s"
            params.append(channel)
        if event_id:
            where += " AND COALESCE(raw->>'EventID', '') = %s"
            params.append(event_id)
        if q:
            where += " AND raw::text ILIKE %s"
            params.append(f"%{q}%")

        cur.execute(f"SELECT count(*) AS n FROM records WHERE {where}", params)
        total = cur.fetchone()["n"]

        cur.execute(
            f"""SELECT
                    id,
                    record_type,
                    ts::text AS ts,
                    COALESCE(raw->>'Channel', '') AS channel,
                    COALESCE(raw->>'EventID', '') AS event_id,
                    COALESCE(
                        raw->'EventData'->>'TargetUserName',
                        raw->'EventData'->>'SubjectUserName',
                        raw->'EventData'->>'Image',
                        raw->'EventData'->>'CommandLine',
                        raw->'EventData'->>'ScriptBlockText',
                        raw->'EventData'->>'IpAddress',
                        raw->>'alert_signature',
                        raw->>'query',
                        raw->>'host',
                        ''
                    ) AS summary_hint
               FROM records
               WHERE {where}
               ORDER BY ts DESC NULLS LAST
               LIMIT %s OFFSET %s""",
            params + [limit, offset],
        )
        records = cur.fetchall()

    return templates.TemplateResponse(request, "records.html", _ctx(
        request, user, "records", case_id=case_id,
        records=records, record_types=record_types,
        type_filter=type, total=total, offset=offset, limit=limit,
        search_q=q, channel_filter=channel, event_id_filter=event_id,
        win_channels=win_channels,
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

    highlights = _record_highlights(record["record_type"], record.get("raw"))
    context_counts = _record_context_counts(case_id, record["record_type"], record.get("raw"))
    interpretation = _record_interpretation(record["record_type"], record.get("raw"))
    rule_recommendations = build_rule_recommendations(case_id, record["record_type"], record.get("raw"))
    can_build_sigma = record["record_type"].startswith("win_evt_")
    can_build_suricata = record["record_type"].startswith(("suricata_", "zeek_", "tshark_"))

    raw_json = json.dumps(record["raw"], indent=2, default=str) if record["raw"] else "{}"

    return templates.TemplateResponse(request, "record_detail.html", _ctx(
        request, user, "records", case_id=case_id,
        record=record, entities=entities, raw_json=raw_json,
        highlights=highlights, context_counts=context_counts,
        interpretation=interpretation,
        rule_recommendations=rule_recommendations,
        can_build_sigma=can_build_sigma,
        can_build_suricata=can_build_suricata,
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

    return templates.TemplateResponse(request, "tasks.html", _ctx(
        request, user, "tasks", case_id=case_id, tasks=tasks,
    ))


@router.get("/cases/{case_id}/tasks/new", response_class=HTMLResponse)
async def task_new_form(request: Request, case_id: str):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)
    return templates.TemplateResponse(request, "task_new.html", _ctx(request, user, "tasks", case_id=case_id))


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
            "INSERT INTO tasks (case_id, title, description, status, assigned_to) VALUES (%s, %s, %s, 'pending', %s) RETURNING id",
            (case_id, question, f"max_steps={max_steps}", user.get("sub")),
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

    return templates.TemplateResponse(request, "task_detail.html", _ctx(
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
            """SELECT f.id, f.title, f.body AS summary, f.severity,
                      f.evidence_ids, f.mitre_ids,
                      f.created_at::text AS created_at,
                      t.assigned_to AS owner_id
               FROM findings f
               LEFT JOIN tasks t ON t.id = f.task_id
               WHERE f.case_id = %s
               ORDER BY f.created_at DESC""",
            (case_id,),
        )
        findings = cur.fetchall()

    return templates.TemplateResponse(request, "findings.html", _ctx(
        request, user, "findings", case_id=case_id, findings=findings,
    ))


@router.post("/cases/{case_id}/findings/{finding_id}/delete")
async def finding_delete(request: Request, case_id: str, finding_id: int):
    """Delete a finding. Admins can delete any; others can only delete their own."""
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    role = user.get("role", "")
    if role == "llm_agent":
        return RedirectResponse(url=f"/ui/cases/{case_id}/findings", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            """SELECT f.id, t.assigned_to AS owner_id
               FROM findings f
               LEFT JOIN tasks t ON t.id = f.task_id
               WHERE f.id = %s AND f.case_id = %s""",
            (finding_id, case_id),
        )
        finding = cur.fetchone()
        if not finding:
            return RedirectResponse(url=f"/ui/cases/{case_id}/findings", status_code=303)

        # Admins can delete any finding; others only their own
        if role != "admin" and finding["owner_id"] != user.get("sub"):
            return RedirectResponse(url=f"/ui/cases/{case_id}/findings", status_code=303)

        cur.execute("DELETE FROM findings WHERE id = %s AND case_id = %s", (finding_id, case_id))
        cur.connection.commit()

    return RedirectResponse(url=f"/ui/cases/{case_id}/findings", status_code=303)


# ── Ingest ──────────────────────────────────────────

@router.get("/cases/{case_id}/ingest", response_class=HTMLResponse)
async def ingest_page(request: Request, case_id: str, message: str = "", error: str = ""):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    registry = get_registry()
    handlers = sorted(registry.ingest_handlers.keys())
    background_jobs = []
    recent_record_counts = []

    with get_cursor() as cur:
        try:
            _fix_stale_jobs(cur, case_id)
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
            background_jobs = cur.fetchall()
        except Exception:
            background_jobs = []

        cur.execute(
            """SELECT record_type, count(*) AS count
               FROM records
               WHERE case_id = %s AND record_type != 'worklog_step'
               GROUP BY record_type
               ORDER BY count DESC, record_type
               LIMIT 12""",
            (case_id,),
        )
        recent_record_counts = cur.fetchall()

    return templates.TemplateResponse(request, "ingest.html", _ctx(
        request, user, "ingest", case_id=case_id,
        handlers=handlers, message=message, error=error,
        background_jobs=background_jobs,
        recent_record_counts=recent_record_counts,
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


@router.post("/cases/{case_id}/ingest/evtx")
async def ingest_evtx_submit(
    request: Request, case_id: str,
    file: UploadFile = File(...),
):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    registry = get_registry()

    fname = file.filename or "upload.evtx"
    suffix = Path(fname).suffix.lower()
    if suffix != ".evtx":
        return RedirectResponse(
            url=f"/ui/cases/{case_id}/ingest?error=Invalid+file+type:+{suffix}+(expected+.evtx)",
            status_code=303,
        )

    try:
        from tempfile import NamedTemporaryFile
        from urllib.parse import quote

        from sphinx.plugins.sphinx_plugin_winevt.evtx import parse_evtx

        content = await file.read()
        with NamedTemporaryFile(prefix="sphinx_evtx_", suffix=".evtx", delete=True) as tmp:
            tmp.write(content)
            tmp.flush()
            grouped, stats = parse_evtx(tmp.name)

        inserted_total = 0
        inserted_by_type: list[str] = []

        for record_type, records in grouped.items():
            handler = registry.ingest_handlers.get(record_type)
            if not handler:
                continue
            inserted = handler(case_id, records)
            inserted_total += inserted
            inserted_by_type.append(f"{record_type}:{inserted}")

        if inserted_total == 0:
            err = (
                f"No supported Windows events found in {fname}. "
                f"Parsed={stats['total_events']}, unsupported={stats['unsupported_events']}, "
                f"errors={stats['parse_errors']}"
            )
            return RedirectResponse(
                url=f"/ui/cases/{case_id}/ingest?error={quote(err)}",
                status_code=303,
            )

        detail = ", ".join(inserted_by_type)
        msg = (
            f"Ingested {inserted_total} Windows event records from {fname} "
            f"({detail}). Unsupported={stats['unsupported_events']}, parse_errors={stats['parse_errors']}"
        )
        return RedirectResponse(
            url=f"/ui/cases/{case_id}/ingest?message={quote(msg)}",
            status_code=303,
        )
    except ImportError as e:
        return RedirectResponse(
            url=f"/ui/cases/{case_id}/ingest?error=EVTX+support+is+not+installed:+{e}",
            status_code=303,
        )
    except Exception as e:
        log.error("EVTX ingest failed: %s", e)
        return RedirectResponse(
            url=f"/ui/cases/{case_id}/ingest?error=EVTX+ingest+failed:+{e}",
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

    # Fetch case-specific HOME_NET for Suricata
    _case_home_net = None
    try:
        with get_cursor() as cur:
            cur.execute("SELECT home_net FROM cases WHERE id = %s", (case_id,))
            row = cur.fetchone()
            if row and row["home_net"]:
                _case_home_net = "[" + ",".join(row["home_net"]) + "]"
    except Exception:
        pass

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
                result = client.pcap_convert(case_id, str(pcap_path), job_id=_job_id, home_net=_case_home_net)
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
            # Auto-fix stale running jobs on access
            try:
                _fix_stale_jobs(cur, case_id)
            except Exception:
                try:
                    cur.connection.rollback()
                except Exception:
                    pass

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
    status = row["status"]

    # If DB says running but no in-memory entry exists (API restarted),
    # and the job has inserted records, it actually finished.
    if status == "running" and summary.get("total_inserted", 0) > 0:
        status = "done"
        summary["stage"] = "complete"
        summary["pct"] = 100

    data = {
        "status": status,
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

    return templates.TemplateResponse(request, "entities.html", _ctx(
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
        # Total count for this entity
        cur.execute(
            """SELECT count(DISTINCT r.id) AS cnt
               FROM entities e JOIN records r ON r.id = e.record_id
               WHERE e.case_id = %s AND e.value = %s AND e.entity_type = %s""",
            (case_id, value, type),
        )
        total_refs = cur.fetchone()["cnt"]

        # Records containing this entity (paginated to avoid timeout)
        cur.execute(
            """SELECT DISTINCT r.id, r.record_type, r.ts::text AS ts
               FROM entities e
               JOIN records r ON r.id = e.record_id
               WHERE e.case_id = %s AND e.value = %s AND e.entity_type = %s
               ORDER BY r.ts DESC NULLS LAST
               LIMIT 200""",
            (case_id, value, type),
        )
        records = cur.fetchall()

        # Record types (from the full set, not just the page)
        cur.execute(
            """SELECT DISTINCT r.record_type
               FROM entities e JOIN records r ON r.id = e.record_id
               WHERE e.case_id = %s AND e.value = %s AND e.entity_type = %s""",
            (case_id, value, type),
        )
        record_types = sorted(r["record_type"] for r in cur.fetchall())

        # Co-occurring entities — use a sample of record IDs to keep fast
        record_ids = [r["id"] for r in records[:100]]
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

    return templates.TemplateResponse(request, "entity_pivot.html", _ctx(
        request, user, "entities", case_id=case_id,
        value=value, entity_type=type,
        records=records, record_types=record_types,
        related_entities=related_entities,
        total_refs=total_refs,
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

    return templates.TemplateResponse(request, "analytics.html", _ctx(
        request, user, "analytics", case_id=case_id,
        analytics_enabled=analytics_enabled,
        attack_windows_presets=ATTACK_WINDOWS_PRESETS,
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

    return templates.TemplateResponse(request, "correlator_new_case.html", _ctx(
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

    return templates.TemplateResponse(request, "notes.html", _ctx(
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
        return templates.TemplateResponse(request, "report.html", _ctx(
            request, user, "report", case_id=case_id, report=report, error=None,
        ))
    except Exception as e:
        log.error("Report generation failed: %s", e)
        return templates.TemplateResponse(request, "report.html", _ctx(
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


# ── User Manual ──────────────────────────────────────

_MANUAL_HTML: str | None = None


def _load_manual_html() -> str:
    """Load and convert the user manual markdown to HTML (cached)."""
    global _MANUAL_HTML
    if _MANUAL_HTML is not None:
        return _MANUAL_HTML
    try:
        import markdown as _md

        manual_path = _HERE.parent.parent.parent / "docs" / "user_manual.md"
        md_text = manual_path.read_text(encoding="utf-8")
        _MANUAL_HTML = _md.markdown(md_text, extensions=["tables", "fenced_code"])
    except Exception as e:
        log.error("Failed to load user manual: %s", e)
        _MANUAL_HTML = "<p>User manual could not be loaded.</p>"
    return _MANUAL_HTML


@router.get("/manual", response_class=HTMLResponse)
async def user_manual_page(request: Request):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)
    manual_html = _load_manual_html()
    return templates.TemplateResponse(request, "user_manual.html", _ctx(
        request, user, "user_manual", manual_html=manual_html,
    ))


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

    return templates.TemplateResponse(request, "admin_users.html", _ctx(
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

    return templates.TemplateResponse(request, "admin_user_detail.html", _ctx(
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

    # Scratch precomputed can reference tasks via task_id FK
    cur.execute(
        "DELETE FROM scratch_precomputed WHERE task_id IN (SELECT id FROM tasks WHERE case_id = %s)",
        (case_id,),
    )
    counts["scratch_precomputed_by_task"] = cur.rowcount

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

    # Background jobs (records FK must be cleared first — handled by _delete_case_evidence)
    cur.execute("DELETE FROM background_jobs WHERE case_id = %s", (case_id,))
    counts["background_jobs"] = cur.rowcount

    # Case assignments
    cur.execute("DELETE FROM case_assignments WHERE case_id = %s", (case_id,))
    counts["case_assignments"] = cur.rowcount

    # Detection rules — don't delete, just clear the case_id (rules are global assets)
    try:
        cur.execute(
            "UPDATE detection_rules SET case_id = '' WHERE case_id = %s",
            (case_id,),
        )
        counts["detection_rules_detached"] = cur.rowcount
    except Exception:
        pass  # table may not exist yet

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
        # Fix stale jobs globally (not scoped to a single case)
        try:
            _fix_stale_jobs(cur)
        except Exception:
            pass

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

        # All tasks with case names
        cur.execute("""
            SELECT t.id, t.case_id, t.title, t.status,
                   t.created_at::text AS created_at,
                   c.name AS case_name
            FROM tasks t
            JOIN cases c ON c.id = t.case_id
            ORDER BY t.created_at DESC
            LIMIT 100
        """)
        tasks = cur.fetchall()

        # All detection rules
        try:
            cur.execute("""
                SELECT id, title, rule_type, status, case_name, sid,
                       created_at::text AS created_at
                FROM detection_rules
                ORDER BY created_at DESC
            """)
            detection_rules = cur.fetchall()
        except Exception:
            detection_rules = []

    return templates.TemplateResponse(request, "admin_data.html", _ctx(
        request, user, "admin_data",
        cases=cases, jobs=jobs, tasks=tasks, detection_rules=detection_rules,
        success=success, error=error,
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

    try:
        with get_cursor() as cur:
            cur.execute("SELECT name FROM cases WHERE id = %s", (case_id,))
            case = cur.fetchone()
            if not case:
                return RedirectResponse(url="/ui/admin/data?error=Case+not+found", status_code=303)

            counts = _delete_case_all(cur, case_id)
            cur.connection.commit()

        total = sum(counts.values())
        from urllib.parse import quote
        msg = f"Deleted case and {total - 1} related rows"
        return RedirectResponse(url=f"/ui/admin/data?success={quote(msg)}", status_code=303)
    except Exception as e:
        log.error("Case deletion failed: %s", e)
        from urllib.parse import quote
        return RedirectResponse(url=f"/ui/admin/data?error={quote(str(e)[:100])}", status_code=303)


@router.post("/admin/data/delete-task")
async def admin_delete_task(request: Request, task_id: int = Form(...)):
    """Delete a single task and its worklog steps."""
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    try:
        with get_cursor() as cur:
            cur.execute("SELECT id, title, case_id FROM tasks WHERE id = %s", (task_id,))
            task = cur.fetchone()
            if not task:
                return RedirectResponse(url="/ui/admin/data?error=Task+not+found", status_code=303)

            # Delete scratch precomputed referencing this task
            cur.execute("DELETE FROM scratch_precomputed WHERE task_id = %s", (task_id,))

            # Delete worklog steps
            cur.execute("DELETE FROM worklog_steps WHERE task_id = %s", (task_id,))
            steps_deleted = cur.rowcount

            # Delete the task itself
            cur.execute("DELETE FROM tasks WHERE id = %s", (task_id,))
            cur.connection.commit()

        from urllib.parse import quote
        msg = f"Deleted task #{task_id} '{task['title']}' and {steps_deleted} worklog steps"
        return RedirectResponse(url=f"/ui/admin/data?success={quote(msg)}", status_code=303)
    except Exception as e:
        log.error("Task deletion failed: %s", e)
        from urllib.parse import quote
        return RedirectResponse(url=f"/ui/admin/data?error={quote(str(e)[:100])}", status_code=303)


@router.post("/admin/data/delete-rule")
async def admin_delete_rule(request: Request, rule_id: int = Form(...)):
    """Delete a detection rule. If deployed, rebuild the Suricata rules file."""
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    try:
        with get_cursor() as cur:
            cur.execute("SELECT id, title, rule_type, status FROM detection_rules WHERE id = %s", (rule_id,))
            rule = cur.fetchone()
            if not rule:
                return RedirectResponse(url="/ui/admin/data?error=Rule+not+found", status_code=303)

            was_deployed = rule["status"] == "deployed" and rule["rule_type"] == "suricata"

            cur.execute("DELETE FROM detection_rules WHERE id = %s", (rule_id,))
            cur.connection.commit()

        # Rebuild Suricata rules file if a deployed rule was deleted
        if was_deployed:
            from sphinx.core.sig_generator import _rebuild_suricata_rules_file
            _rebuild_suricata_rules_file()

        from urllib.parse import quote
        msg = f"Deleted rule #{rule_id} ({rule['title']})"
        return RedirectResponse(url=f"/ui/admin/data?success={quote(msg)}", status_code=303)
    except Exception as e:
        log.error("Rule deletion failed: %s", e)
        from urllib.parse import quote
        return RedirectResponse(url=f"/ui/admin/data?error={quote(str(e)[:100])}", status_code=303)


@router.get("/admin/data/rules/{rule_id}", response_class=HTMLResponse)
async def admin_rule_edit_page(request: Request, rule_id: int, success: str = "", error: str = ""):
    """Admin page to view/edit a single detection rule."""
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            """SELECT id, title, rule_type, status, description, rule_content,
                      compiled_sql, mitre_ids, sid, case_id, case_name,
                      generated_by, created_at::text AS created_at, updated_at::text AS updated_at
               FROM detection_rules WHERE id = %s""",
            (rule_id,),
        )
        rule = cur.fetchone()
        if not rule:
            return RedirectResponse(url="/ui/admin/data?error=Rule+not+found", status_code=303)

    return templates.TemplateResponse(request, "admin_rule_edit.html", _ctx(
        request, user, "admin_data", rule=rule, success=success, error=error,
    ))


@router.post("/admin/data/rules/{rule_id}/save")
async def admin_rule_save(
    request: Request,
    rule_id: int,
    title: str = Form(...),
    rule_content: str = Form(...),
    description: str = Form(""),
):
    """Save edits to a detection rule (admin only)."""
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    from urllib.parse import quote
    try:
        with get_cursor() as cur:
            cur.execute(
                """UPDATE detection_rules
                   SET title = %s, rule_content = %s, description = %s, updated_at = now()
                   WHERE id = %s""",
                (title, rule_content, description, rule_id),
            )
            if cur.rowcount == 0:
                return RedirectResponse(url="/ui/admin/data?error=Rule+not+found", status_code=303)
            cur.connection.commit()
        return RedirectResponse(url=f"/ui/admin/data/rules/{rule_id}?success=Rule+saved", status_code=303)
    except Exception as e:
        log.error("Rule save failed: %s", e)
        return RedirectResponse(url=f"/ui/admin/data/rules/{rule_id}?error={quote(str(e)[:100])}", status_code=303)


@router.post("/admin/data/rules/{rule_id}/deploy")
async def admin_rule_deploy(request: Request, rule_id: int):
    """Deploy a detection rule (admin only)."""
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    from urllib.parse import quote
    with get_cursor() as cur:
        cur.execute("SELECT rule_type, status FROM detection_rules WHERE id = %s", (rule_id,))
        rule = cur.fetchone()
        if not rule:
            return RedirectResponse(url="/ui/admin/data?error=Rule+not+found", status_code=303)

        # Auto-approve if still pending
        if rule["status"] in ("pending_review", "draft"):
            cur.execute(
                "UPDATE detection_rules SET status = 'approved', updated_at = now() WHERE id = %s",
                (rule_id,),
            )
            cur.connection.commit()

    try:
        if rule["rule_type"] == "suricata":
            from sphinx.core.sig_generator import deploy_suricata_rule
            ok = deploy_suricata_rule(rule_id)
            if ok:
                return RedirectResponse(url=f"/ui/admin/data/rules/{rule_id}?success=Suricata+rule+deployed", status_code=303)
            return RedirectResponse(url=f"/ui/admin/data/rules/{rule_id}?error=Deploy+failed", status_code=303)
        elif rule["rule_type"] == "sigma":
            from sphinx.core.sig_generator import compile_sigma_rule
            ok = compile_sigma_rule(rule_id)
            msg = "Sigma+rule+compiled+and+deployed" if ok else "Sigma+compile+failed"
            status = "success" if ok else "error"
            return RedirectResponse(url=f"/ui/admin/data/rules/{rule_id}?{status}={msg}", status_code=303)
    except Exception as e:
        log.error("Admin rule deploy failed: %s", e)
        return RedirectResponse(url=f"/ui/admin/data/rules/{rule_id}?error={quote(str(e)[:80])}", status_code=303)

    return RedirectResponse(url=f"/ui/admin/data/rules/{rule_id}?error=Unknown+rule+type", status_code=303)


@router.post("/admin/data/import-rules")
async def admin_import_rules(request: Request, file: UploadFile = File(...)):
    """Import Suricata (.rules) or Sigma (.yml/.yaml) rules from an uploaded file."""
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    from urllib.parse import quote
    filename = file.filename or "unknown"

    if not filename.endswith((".rules", ".yml", ".yaml")):
        return RedirectResponse(
            url=f"/ui/admin/data?error={quote('Unsupported file type. Upload .rules, .yml, or .yaml files.')}",
            status_code=303,
        )

    try:
        content = (await file.read()).decode("utf-8", errors="replace")
        from sphinx.core.sig_generator import import_rules_from_file, import_rules_to_db
        parsed = import_rules_from_file(content, filename)
        if not parsed:
            return RedirectResponse(
                url=f"/ui/admin/data?error={quote(f'No rules found in {filename}')}",
                status_code=303,
            )
        inserted = import_rules_to_db(parsed)
        skipped = len(parsed) - inserted
        msg = f"Imported {inserted} rules from {filename}"
        if skipped:
            msg += f" ({skipped} duplicates skipped)"
        return RedirectResponse(url=f"/ui/admin/data?success={quote(msg)}", status_code=303)
    except Exception as e:
        log.error("Rule import failed: %s", e)
        return RedirectResponse(url=f"/ui/admin/data?error={quote(str(e)[:100])}", status_code=303)


# ── Admin: Query Learning ──────────────────────────

@router.get("/admin/query-learning", response_class=HTMLResponse)
async def admin_query_learning_page(request: Request, filter: str = "", success: str = "", error: str = ""):
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    from sphinx.core.query_learner import list_patterns

    patterns = list_patterns(status_filter=filter or None, min_frequency=2)

    # Counts for filter tabs
    with get_cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM query_patterns")
        count_all = cur.fetchone()["n"]
        cur.execute("SELECT count(*) AS n FROM query_patterns WHERE NOT promoted AND NOT COALESCE(dismissed, false) AND frequency >= 2")
        count_candidates = cur.fetchone()["n"]
        cur.execute("SELECT count(*) AS n FROM query_patterns WHERE promoted")
        count_promoted = cur.fetchone()["n"]
        cur.execute("SELECT count(*) AS n FROM query_patterns WHERE COALESCE(dismissed, false)")
        count_dismissed = cur.fetchone()["n"]

    counts = {
        "all": count_all,
        "candidates": count_candidates,
        "promoted": count_promoted,
        "dismissed": count_dismissed,
    }

    return templates.TemplateResponse(request, "admin_query_learning.html", _ctx(
        request, user, "admin_query_learning",
        patterns=patterns, filter=filter, counts=counts,
        success=success, error=error,
    ))


@router.post("/admin/query-learning/mine")
async def admin_query_learning_mine(request: Request):
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    from sphinx.core.query_learner import mine_worklog
    result = mine_worklog(min_frequency=2)

    msg = f"Mined {result['patterns_found']} patterns ({result['new']} new, {result['updated']} updated, {len(result.get('promotion_candidates', []))} candidates)"
    return RedirectResponse(url=f"/ui/admin/query-learning?success={msg.replace(' ', '+')}", status_code=303)


@router.post("/admin/query-learning/{pattern_hash}/promote")
async def admin_query_learning_promote(request: Request, pattern_hash: str, precompute_fn: str = Form("")):
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    if not precompute_fn.strip():
        return RedirectResponse(url="/ui/admin/query-learning?error=Precompute+function+path+is+required", status_code=303)

    from sphinx.core.query_learner import promote_pattern
    if promote_pattern(pattern_hash, precompute_fn.strip()):
        return RedirectResponse(url="/ui/admin/query-learning?success=Pattern+promoted", status_code=303)
    return RedirectResponse(url="/ui/admin/query-learning?error=Pattern+not+found", status_code=303)


@router.post("/admin/query-learning/{pattern_hash}/dismiss")
async def admin_query_learning_dismiss(request: Request, pattern_hash: str):
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    from sphinx.core.query_learner import dismiss_pattern
    dismiss_pattern(pattern_hash, reviewed_by=user.get("sub", ""))
    return RedirectResponse(url="/ui/admin/query-learning?success=Pattern+dismissed", status_code=303)


@router.post("/admin/query-learning/{pattern_hash}/undismiss")
async def admin_query_learning_undismiss(request: Request, pattern_hash: str):
    user = _require_admin(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            "UPDATE query_patterns SET dismissed = false WHERE pattern_hash = %s",
            (pattern_hash,),
        )
        cur.connection.commit()
    return RedirectResponse(url="/ui/admin/query-learning?success=Pattern+restored", status_code=303)


# ── Detection Rules ────────────────────────────────

@router.get("/cases/{case_id}/detection-rules", response_class=HTMLResponse)
async def detection_rules_list(request: Request, case_id: str, filter: str = "", success: str = "", error: str = ""):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        # Show rules for this case + detached rules (global assets)
        case_filter = "(case_id = %s OR case_id = '' OR case_id IS NULL)"
        case_params = [case_id]

        # Counts for filter tabs
        cur.execute(f"SELECT count(*) AS n FROM detection_rules WHERE {case_filter}", case_params)
        count_all = cur.fetchone()["n"]
        cur.execute(f"SELECT count(*) AS n FROM detection_rules WHERE {case_filter} AND status = 'pending_review'", case_params)
        count_pending = cur.fetchone()["n"]
        cur.execute(f"SELECT count(*) AS n FROM detection_rules WHERE {case_filter} AND status = 'approved'", case_params)
        count_approved = cur.fetchone()["n"]
        cur.execute(f"SELECT count(*) AS n FROM detection_rules WHERE {case_filter} AND status = 'deployed'", case_params)
        count_deployed = cur.fetchone()["n"]

        where = case_filter
        params = list(case_params)
        if filter:
            where += " AND status = %s"
            params.append(filter)

        cur.execute(
            f"""SELECT id, title, rule_type, status, mitre_ids, case_id, case_name,
                       created_at::text AS created_at
                FROM detection_rules WHERE {where}
                ORDER BY created_at DESC""",
            params,
        )
        rules = cur.fetchall()

    counts = {"all": count_all, "pending_review": count_pending, "approved": count_approved, "deployed": count_deployed}

    return templates.TemplateResponse(request, "detection_rules.html", _ctx(
        request, user, "detection_rules", case_id=case_id,
        rules=rules, filter=filter, counts=counts,
        success=success, error=error,
    ))


@router.get("/cases/{case_id}/detection-rules/new", response_class=HTMLResponse)
async def detection_rule_new_form(
    request: Request,
    case_id: str,
    error: str = "",
    title: str = "",
    rule_type: str = "",
    description: str = "",
    rule_content: str = "",
):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)
    return templates.TemplateResponse(request, "detection_rule_new.html", _ctx(
        request, user, "detection_rules", case_id=case_id, error=error,
        form_title=title,
        form_rule_type=rule_type or "suricata",
        form_description=description,
        form_rule_content=rule_content,
    ))


@router.get("/cases/{case_id}/detection-rules/builder", response_class=HTMLResponse)
async def detection_rule_builder_entry(request: Request, case_id: str, record_id: str = ""):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    source_record = None
    suggested_rule_type = ""
    if record_id:
        with get_cursor() as cur:
            cur.execute(
                "SELECT id, record_type, ts::text AS ts, raw FROM records WHERE id = %s AND case_id = %s",
                (record_id, case_id),
            )
            source_record = cur.fetchone()
        if source_record:
            suggested_rule_type = _suggest_rule_type(source_record["record_type"])

    return templates.TemplateResponse(request, "detection_rule_builder.html", _ctx(
        request, user, "detection_rules", case_id=case_id,
        source_record=source_record,
        suggested_rule_type=suggested_rule_type,
    ))


@router.get("/cases/{case_id}/detection-rules/builder/sigma", response_class=HTMLResponse)
async def detection_rule_builder_sigma(
    request: Request,
    case_id: str,
    record_id: str = "",
    channel: str = "",
):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    source_record = None
    source_event_data_items: list[dict] = []
    source_channel = ""
    source_event_id = ""
    source_recommendations = None

    if record_id:
        with get_cursor() as cur:
            cur.execute(
                "SELECT id, record_type, ts::text AS ts, raw FROM records WHERE id = %s AND case_id = %s",
                (record_id, case_id),
            )
            source_record = cur.fetchone()

    if source_record and isinstance(source_record.get("raw"), dict):
        raw = source_record["raw"]
        source_channel = str(raw.get("Channel") or "")
        source_event_id = str(raw.get("EventID") or "")
        event_data = raw.get("EventData") or {}
        if isinstance(event_data, dict):
            for key in sorted(event_data.keys()):
                source_event_data_items.append({"key": key, "value": event_data[key]})
        source_recommendations = build_rule_recommendations(case_id, source_record["record_type"], raw)

    selected_channel = channel or source_channel

    with get_cursor() as cur:
        cur.execute(
            """SELECT COALESCE(raw->>'Channel', record_type) AS channel, count(*) AS cnt
               FROM records
               WHERE case_id = %s AND record_type LIKE 'win_evt_%%'
               GROUP BY 1
               ORDER BY cnt DESC, channel""",
            (case_id,),
        )
        channel_counts = cur.fetchall()

        if selected_channel:
            cur.execute(
                """SELECT COALESCE(raw->>'EventID', '?') AS event_id, count(*) AS cnt
                   FROM records
                   WHERE case_id = %s
                     AND record_type LIKE 'win_evt_%%'
                     AND COALESCE(raw->>'Channel', record_type) = %s
                   GROUP BY 1
                   ORDER BY cnt DESC, event_id
                   LIMIT 25""",
                (case_id, selected_channel),
            )
        else:
            cur.execute(
                """SELECT COALESCE(raw->>'EventID', '?') AS event_id, count(*) AS cnt
                   FROM records
                   WHERE case_id = %s AND record_type LIKE 'win_evt_%%'
                   GROUP BY 1
                   ORDER BY cnt DESC, event_id
                   LIMIT 25""",
                (case_id,),
            )
        top_event_ids = cur.fetchall()

        if selected_channel:
            cur.execute(
                """SELECT k.key AS key_name, count(*) AS cnt
                   FROM records r
                   CROSS JOIN LATERAL jsonb_object_keys(COALESCE(r.raw->'EventData', '{}'::jsonb)) AS k(key)
                   WHERE r.case_id = %s
                     AND r.record_type LIKE 'win_evt_%%'
                     AND COALESCE(r.raw->>'Channel', r.record_type) = %s
                   GROUP BY k.key
                   ORDER BY cnt DESC, key_name
                   LIMIT 50""",
                (case_id, selected_channel),
            )
        else:
            cur.execute(
                """SELECT k.key AS key_name, count(*) AS cnt
                   FROM records r
                   CROSS JOIN LATERAL jsonb_object_keys(COALESCE(r.raw->'EventData', '{}'::jsonb)) AS k(key)
                   WHERE r.case_id = %s
                     AND r.record_type LIKE 'win_evt_%%'
                   GROUP BY k.key
                   ORDER BY cnt DESC, key_name
                   LIMIT 50""",
                (case_id,),
            )
        observed_keys = cur.fetchall()

    starter_rule = _build_sigma_starter(source_record, selected_channel, source_event_id)

    return templates.TemplateResponse(request, "detection_rule_builder_sigma.html", _ctx(
        request, user, "detection_rules", case_id=case_id,
        source_record=source_record,
        source_channel=source_channel,
        source_event_id=source_event_id,
        source_event_data_items=source_event_data_items,
        source_recommendations=source_recommendations,
        selected_channel=selected_channel,
        channel_counts=channel_counts,
        top_event_ids=top_event_ids,
        observed_keys=observed_keys,
        starter_rule=starter_rule,
    ))


@router.get("/cases/{case_id}/detection-rules/builder/suricata", response_class=HTMLResponse)
async def detection_rule_builder_suricata(request: Request, case_id: str, record_id: str = ""):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    source_record = None
    source_recommendations = None
    if record_id:
        with get_cursor() as cur:
            cur.execute(
                "SELECT id, record_type, ts::text AS ts, raw FROM records WHERE id = %s AND case_id = %s",
                (record_id, case_id),
            )
            source_record = cur.fetchone()
        if source_record:
            source_recommendations = build_rule_recommendations(case_id, source_record["record_type"], source_record.get("raw"))

    if source_record and source_record["record_type"].startswith("tshark_"):
        raw = source_record.get("raw") or {}
        content = ""
        if isinstance(raw, dict):
            for key in ("ascii_printable", "payload", "stream_text", "data"):
                value = raw.get(key)
                if isinstance(value, str) and value.strip():
                    content = value.strip()
                    break
        if len(content) > 120:
            content = content[:117] + "..."
    else:
        content = ""

    cleaned_content = content.replace('"', "") if content else ""

    starter_rule = "\n".join([
        "alert http $HOME_NET any -> $EXTERNAL_NET any (",
        '  msg:"EvidenceLab analyst-authored detection";',
        '  flow:established,to_server;',
        f'  content:"{cleaned_content}";' if cleaned_content else '  content:"replace-me";',
        "  classtype:trojan-activity;",
        "  sid:9100001;",
        "  rev:1;",
        ")",
    ])

    return templates.TemplateResponse(request, "detection_rule_builder_suricata.html", _ctx(
        request, user, "detection_rules", case_id=case_id,
        source_record=source_record,
        source_recommendations=source_recommendations,
        starter_rule=starter_rule,
    ))


@router.post("/cases/{case_id}/detection-rules/new")
async def detection_rule_new_submit(
    request: Request, case_id: str,
    title: str = Form(...),
    rule_type: str = Form(...),
    rule_content: str = Form(...),
    description: str = Form(""),
    action: str = Form("create"),
):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    # Get case name for provenance
    case_name = ""
    with get_cursor() as cur:
        cur.execute("SELECT name FROM cases WHERE id = %s", (case_id,))
        row = cur.fetchone()
        if row:
            case_name = row["name"]

    # Assign SID for Suricata rules
    sid = None
    if rule_type == "suricata":
        from sphinx.core.sig_generator import _next_suricata_sid
        sid = _next_suricata_sid()

    status = "approved" if action == "create_and_deploy" else "pending_review"

    with get_cursor() as cur:
        cur.execute(
            """INSERT INTO detection_rules
               (case_id, case_name, rule_type, status, title, description,
                rule_content, generated_by, sid)
               VALUES (%s, %s, %s, %s, %s, %s, %s, 'manual', %s)
               RETURNING id""",
            (case_id, case_name, rule_type, status, title, description,
             rule_content, sid),
        )
        rule_id = cur.fetchone()["id"]
        cur.connection.commit()

    # Auto-deploy if requested
    if action == "create_and_deploy":
        try:
            if rule_type == "suricata":
                from sphinx.core.sig_generator import deploy_suricata_rule
                deploy_suricata_rule(rule_id)
            elif rule_type == "sigma":
                from sphinx.core.sig_generator import compile_sigma_rule
                compile_sigma_rule(rule_id)
        except Exception as e:
            log.warning("Auto-deploy failed for rule %d: %s", rule_id, e)

    return RedirectResponse(
        url=f"/ui/cases/{case_id}/detection-rules/{rule_id}?success=Rule+created",
        status_code=303,
    )


@router.post("/cases/{case_id}/findings/generate-rules")
async def generate_rules_submit(request: Request, case_id: str):
    """Generate detection rules from selected findings."""
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    form = await request.form()
    finding_ids = [int(x) for x in form.getlist("finding_ids")]

    if not finding_ids:
        return RedirectResponse(
            url=f"/ui/cases/{case_id}/findings",
            status_code=303,
        )

    from sphinx.core.sig_generator import generate_rules_for_findings
    settings = request.app.state.settings
    created = generate_rules_for_findings(settings, finding_ids, case_id)

    msg = f"Generated {len(created)} detection rule(s) from {len(finding_ids)} finding(s)"
    return RedirectResponse(
        url=f"/ui/cases/{case_id}/detection-rules?success={msg.replace(' ', '+')}",
        status_code=303,
    )


@router.get("/cases/{case_id}/detection-rules/{rule_id}", response_class=HTMLResponse)
async def detection_rule_detail(request: Request, case_id: str, rule_id: int, success: str = "", error: str = ""):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            """SELECT *, created_at::text AS created_at, updated_at::text AS updated_at
               FROM detection_rules WHERE id = %s AND (case_id = %s OR case_id = '' OR case_id IS NULL)""",
            (rule_id, case_id),
        )
        rule = cur.fetchone()
        if not rule:
            return RedirectResponse(url=f"/ui/cases/{case_id}/detection-rules?error=Rule+not+found", status_code=303)

        # Fetch linked finding
        finding = None
        if rule.get("finding_id"):
            cur.execute("SELECT * FROM findings WHERE id = %s", (rule["finding_id"],))
            finding = cur.fetchone()

    return templates.TemplateResponse(request, "rule_review.html", _ctx(
        request, user, "detection_rules", case_id=case_id,
        rule=rule, finding=finding, success=success, error=error,
    ))


@router.post("/cases/{case_id}/detection-rules/{rule_id}/edit")
async def detection_rule_edit(request: Request, case_id: str, rule_id: int, rule_content: str = Form(...)):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            "UPDATE detection_rules SET rule_content = %s, updated_at = now() WHERE id = %s AND (case_id = %s OR case_id = '' OR case_id IS NULL)",
            (rule_content, rule_id, case_id),
        )
        cur.connection.commit()

    return RedirectResponse(url=f"/ui/cases/{case_id}/detection-rules/{rule_id}?success=Rule+updated", status_code=303)


@router.post("/cases/{case_id}/detection-rules/{rule_id}/approve")
async def detection_rule_approve(request: Request, case_id: str, rule_id: int):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            "UPDATE detection_rules SET status = 'approved', reviewed_by = %s, updated_at = now() WHERE id = %s AND (case_id = %s OR case_id = '' OR case_id IS NULL)",
            (user.get("sub", ""), rule_id, case_id),
        )
        cur.connection.commit()

    return RedirectResponse(url=f"/ui/cases/{case_id}/detection-rules/{rule_id}?success=Rule+approved", status_code=303)


@router.post("/cases/{case_id}/detection-rules/{rule_id}/reject")
async def detection_rule_reject(request: Request, case_id: str, rule_id: int):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            "UPDATE detection_rules SET status = 'rejected', reviewed_by = %s, updated_at = now() WHERE id = %s AND (case_id = %s OR case_id = '' OR case_id IS NULL)",
            (user.get("sub", ""), rule_id, case_id),
        )
        cur.connection.commit()

    return RedirectResponse(url=f"/ui/cases/{case_id}/detection-rules/{rule_id}?success=Rule+rejected", status_code=303)


@router.post("/cases/{case_id}/detection-rules/{rule_id}/deploy")
async def detection_rule_deploy(request: Request, case_id: str, rule_id: int):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute("SELECT rule_type, status FROM detection_rules WHERE id = %s AND (case_id = %s OR case_id = '' OR case_id IS NULL)", (rule_id, case_id))
        rule = cur.fetchone()
        if not rule:
            return RedirectResponse(url=f"/ui/cases/{case_id}/detection-rules?error=Rule+not+found", status_code=303)

    if rule["rule_type"] == "suricata":
        from sphinx.core.sig_generator import deploy_suricata_rule
        if deploy_suricata_rule(rule_id):
            return RedirectResponse(url=f"/ui/cases/{case_id}/detection-rules/{rule_id}?success=Suricata+rule+deployed", status_code=303)
        return RedirectResponse(url=f"/ui/cases/{case_id}/detection-rules/{rule_id}?error=Deploy+failed", status_code=303)

    elif rule["rule_type"] == "sigma":
        # Compile Sigma to SQL and mark deployed
        try:
            from sphinx.core.sig_generator import compile_sigma_rule
            compiled = compile_sigma_rule(rule_id)
            msg = "Sigma+rule+compiled+and+deployed" if compiled else "Sigma+compile+failed"
            status = "success" if compiled else "error"
            return RedirectResponse(url=f"/ui/cases/{case_id}/detection-rules/{rule_id}?{status}={msg}", status_code=303)
        except Exception as e:
            return RedirectResponse(url=f"/ui/cases/{case_id}/detection-rules/{rule_id}?error=Sigma+deploy+failed:+{str(e)[:50]}", status_code=303)

    return RedirectResponse(url=f"/ui/cases/{case_id}/detection-rules/{rule_id}?error=Unknown+rule+type", status_code=303)


@router.post("/cases/{case_id}/detection-rules/{rule_id}/regenerate")
async def detection_rule_regenerate(request: Request, case_id: str, rule_id: int):
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute("SELECT finding_id, rule_type FROM detection_rules WHERE id = %s AND (case_id = %s OR case_id = '' OR case_id IS NULL)", (rule_id, case_id))
        rule = cur.fetchone()
        if not rule or not rule["finding_id"]:
            return RedirectResponse(url=f"/ui/cases/{case_id}/detection-rules/{rule_id}?error=Cannot+regenerate", status_code=303)

    from sphinx.core.sig_generator import fetch_evidence_for_finding, generate_sigma_rule, generate_suricata_rule
    settings = request.app.state.settings
    finding, evidence = fetch_evidence_for_finding(rule["finding_id"])

    try:
        if rule["rule_type"] == "sigma":
            result = generate_sigma_rule(settings, finding, evidence)
        else:
            result = generate_suricata_rule(settings, finding, evidence)

        with get_cursor() as cur:
            cur.execute(
                "UPDATE detection_rules SET rule_content = %s, status = 'pending_review', updated_at = now() WHERE id = %s",
                (result["rule_content"], rule_id),
            )
            cur.connection.commit()

        return RedirectResponse(url=f"/ui/cases/{case_id}/detection-rules/{rule_id}?success=Rule+regenerated", status_code=303)
    except Exception as e:
        return RedirectResponse(url=f"/ui/cases/{case_id}/detection-rules/{rule_id}?error=Regeneration+failed", status_code=303)


@router.get("/cases/{case_id}/detection-rules/{rule_id}/export")
async def detection_rule_export(request: Request, case_id: str, rule_id: int):
    """Download a detection rule as a file."""
    user = _get_user(request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    with get_cursor() as cur:
        cur.execute(
            "SELECT title, rule_type, rule_content FROM detection_rules WHERE id = %s AND (case_id = %s OR case_id = '' OR case_id IS NULL)",
            (rule_id, case_id),
        )
        rule = cur.fetchone()
        if not rule:
            return HTMLResponse("Rule not found", status_code=404)

    ext = "yml" if rule["rule_type"] == "sigma" else "rules"
    filename = f"sphinx-rule-{rule_id}.{ext}"
    from fastapi.responses import Response
    return Response(
        content=rule["rule_content"],
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
