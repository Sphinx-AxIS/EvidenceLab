"""Sphinx ingest routes — evidence upload via plugin handlers."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from sphinx.core.auth import CurrentUser, check_case_access
from sphinx.core.plugin_loader import get_registry

log = logging.getLogger(__name__)

router = APIRouter(prefix="/cases/{case_id}/ingest", tags=["ingest"])

_require_analyst = CurrentUser(required_role="analyst")


class IngestRequest(BaseModel):
    record_type: str = Field(..., description="e.g. suricata_alert, win_evt_security")
    records: list[dict[str, Any]] = Field(..., min_length=1)


class IngestResponse(BaseModel):
    record_type: str
    inserted: int
    message: str


@router.post("", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest_evidence(
    case_id: str, body: IngestRequest, user=Depends(_require_analyst)
):
    """Ingest evidence records using the appropriate plugin handler.

    The record_type must match a registered ingest handler from a loaded plugin.
    """
    check_case_access(user, case_id)

    registry = get_registry()
    handler = registry.ingest_handlers.get(body.record_type)

    if not handler:
        available = sorted(registry.ingest_handlers.keys())
        raise HTTPException(
            status_code=400,
            detail=f"No ingest handler for record_type '{body.record_type}'. "
                   f"Available: {available}",
        )

    try:
        inserted = handler(case_id, body.records)
    except Exception as e:
        log.error("Ingest failed for %s: %s", body.record_type, e)
        raise HTTPException(
            status_code=500,
            detail=f"Ingest failed: {e}",
        )

    return IngestResponse(
        record_type=body.record_type,
        inserted=inserted,
        message=f"Ingested {inserted} {body.record_type} records",
    )


@router.get("/handlers")
async def list_handlers(case_id: str, user=Depends(_require_analyst)):
    """List available ingest handlers from loaded plugins."""
    check_case_access(user, case_id)
    registry = get_registry()
    return {
        "handlers": sorted(registry.ingest_handlers.keys()),
    }