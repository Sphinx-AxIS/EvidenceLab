"""Sphinx dashboard — SQL-driven summary endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from sphinx.core.auth import CurrentUser, check_case_access
from sphinx.core.db import get_cursor
from sphinx.core.models import DashboardSummary
from sphinx.core.plugin_loader import get_registry

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_require_analyst = CurrentUser(required_role="analyst")


@router.get("/{case_id}", response_model=DashboardSummary)
async def get_dashboard(case_id: str, user=Depends(_require_analyst)):
    """Return dashboard summary for a case — all SQL, no LLM."""
    check_case_access(user, case_id)

    with get_cursor() as cur:
        # Case metadata
        cur.execute(
            "SELECT home_net, victim_ips FROM cases WHERE id = %s",
            (case_id,),
        )
        case_row = cur.fetchone()
        home_net = case_row["home_net"] if case_row else []
        victim_ips = case_row["victim_ips"] if case_row else []

        # Record counts by type
        cur.execute(
            """SELECT record_type, count(*) AS cnt
               FROM records WHERE case_id = %s
               GROUP BY record_type ORDER BY cnt DESC""",
            (case_id,),
        )
        record_counts = {row["record_type"]: row["cnt"] for row in cur.fetchall()}

        # Task stats
        cur.execute(
            "SELECT count(*) AS total FROM tasks WHERE case_id = %s",
            (case_id,),
        )
        task_total = cur.fetchone()["total"]

        cur.execute(
            "SELECT count(*) AS done FROM tasks WHERE case_id = %s AND status = 'done'",
            (case_id,),
        )
        task_done = cur.fetchone()["done"]

        # Finding count
        cur.execute(
            "SELECT count(*) AS cnt FROM findings WHERE case_id = %s",
            (case_id,),
        )
        finding_count = cur.fetchone()["cnt"]

    return DashboardSummary(
        case_id=case_id,
        record_counts=record_counts,
        task_total=task_total,
        task_done=task_done,
        finding_count=finding_count,
        home_net=home_net,
        victim_ips=victim_ips,
    )


@router.get("/{case_id}/plugins")
async def get_plugin_status(case_id: str, user=Depends(_require_analyst)):
    """Return loaded plugin status."""
    check_case_access(user, case_id)
    registry = get_registry()
    return {
        "plugins": [
            {"name": name, **info}
            for name, info in registry.plugins.items()
        ],
        "ingest_handlers": list(registry.ingest_handlers.keys()),
        "ocsf_views": list(registry.ocsf_mappers.keys()),
        "precompute_count": len(registry.precompute_fns),
    }