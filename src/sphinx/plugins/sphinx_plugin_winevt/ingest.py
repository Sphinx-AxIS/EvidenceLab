"""Windows Event Log ingest — parsers for EVTX JSON export."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sphinx.core.db import get_cursor
from sphinx.core.entity_extractor import extract_and_store

log = logging.getLogger(__name__)


def _parse_evt_timestamp(raw: dict) -> datetime | None:
    """Extract timestamp from Windows event record."""
    for key in ("TimeCreated", "timestamp", "SystemTime", "ts"):
        val = raw.get(key)
        if val is None:
            # Check nested System.TimeCreated
            system = raw.get("System", {})
            tc = system.get("TimeCreated", {})
            val = tc.get("SystemTime") or tc.get("#text")
        if val and isinstance(val, str):
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
            ):
                try:
                    return datetime.strptime(val, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
    return None


def _ingest_channel(case_id: str, record_type: str, records: list[dict]) -> int:
    """Generic ingest for a Windows event log channel."""
    inserted = 0
    with get_cursor() as cur:
        for raw in records:
            ts = _parse_evt_timestamp(raw)
            cur.execute(
                """INSERT INTO records (case_id, record_type, source_plugin, raw, ts)
                   VALUES (%s, %s, 'sphinx-plugin-winevt', %s, %s)
                   RETURNING id""",
                (case_id, record_type, json.dumps(raw), ts),
            )
            record_id = cur.fetchone()["id"]
            extract_and_store(case_id, record_id, raw)
            inserted += 1
        cur.connection.commit()

    log.info("Ingested %d %s records for case %s", inserted, record_type, case_id)
    return inserted


def ingest_security(case_id: str, records: list[dict]) -> int:
    return _ingest_channel(case_id, "win_evt_security", records)


def ingest_powershell(case_id: str, records: list[dict]) -> int:
    return _ingest_channel(case_id, "win_evt_powershell", records)


def ingest_sysmon(case_id: str, records: list[dict]) -> int:
    return _ingest_channel(case_id, "win_evt_sysmon", records)


def ingest_application(case_id: str, records: list[dict]) -> int:
    return _ingest_channel(case_id, "win_evt_application", records)


def ingest_system(case_id: str, records: list[dict]) -> int:
    return _ingest_channel(case_id, "win_evt_system", records)