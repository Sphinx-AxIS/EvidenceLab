"""Windows Event Log ingest — parsers for EVTX JSON export."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sphinx.core.db import get_cursor
from sphinx.core.entity_extractor import extract_and_store

log = logging.getLogger(__name__)


def _coerce_datetime(value: Any) -> datetime | None:
    """Parse common Windows event timestamp strings into aware UTC datetimes."""
    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    # Handle the common EVTX format "...Z" directly.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    return None


def _parse_evt_timestamp(raw: dict) -> datetime | None:
    """Extract timestamp from Windows event record."""
    candidates: list[Any] = [
        raw.get("timestamp"),
        raw.get("SystemTime"),
        raw.get("TimeCreated"),
        raw.get("ts"),
    ]

    system = raw.get("System", {})
    if isinstance(system, dict):
        candidates.extend([
            system.get("SystemTime"),
            system.get("timestamp"),
        ])
        tc = system.get("TimeCreated", {})
        if isinstance(tc, dict):
            candidates.extend([
                tc.get("SystemTime"),
                tc.get("#text"),
            ])
        else:
            candidates.append(tc)

    for candidate in candidates:
        dt = _coerce_datetime(candidate)
        if dt is not None:
            return dt

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
            extract_and_store(case_id, record_id, raw, cur=cur)
            inserted += 1
        cur.connection.commit()

    log.info("Ingested %d %s records for case %s", inserted, record_type, case_id)

    # Run deployed Sigma rules against newly ingested records
    try:
        from sphinx.core.sig_generator import run_sigma_rules_on_case
        matches = run_sigma_rules_on_case(case_id)
        if matches:
            log.info("Sigma detection: %d matches across %d rules for case %s",
                     len(matches), len({m["rule_id"] for m in matches}), case_id)
    except Exception as e:
        log.warning("Sigma rule execution skipped: %s", e)

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
