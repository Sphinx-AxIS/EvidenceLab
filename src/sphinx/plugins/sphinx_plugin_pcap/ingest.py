"""PCAP plugin ingest — parsers for Suricata, Zeek, and tshark output."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sphinx.core.db import get_cursor
from sphinx.core.entity_extractor import extract_and_store

log = logging.getLogger(__name__)


def _parse_timestamp(raw: dict, *keys: str) -> datetime | None:
    """Try to extract a timestamp from raw data using multiple possible keys."""
    for key in keys:
        val = raw.get(key)
        if val is None:
            continue
        if isinstance(val, (int, float)):
            return datetime.fromtimestamp(val, tz=timezone.utc)
        if isinstance(val, str):
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
            ):
                try:
                    return datetime.strptime(val, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
    return None


def ingest_suricata(case_id: str, records: list[dict]) -> int:
    """Ingest Suricata EVE JSON alert records.

    Expects a list of dicts from eve.json (event_type: alert).
    Returns count of records inserted.
    """
    inserted = 0
    with get_cursor() as cur:
        for raw in records:
            ts = _parse_timestamp(raw, "timestamp")
            cur.execute(
                """INSERT INTO records (case_id, record_type, source_plugin, raw, ts)
                   VALUES (%s, 'suricata_alert', 'sphinx-plugin-pcap', %s, %s)
                   RETURNING id""",
                (case_id, json.dumps(raw), ts),
            )
            record_id = cur.fetchone()["id"]
            extract_and_store(case_id, record_id, raw)
            inserted += 1
        cur.connection.commit()

    log.info("Ingested %d Suricata alerts for case %s", inserted, case_id)
    return inserted


def ingest_zeek_conn(case_id: str, records: list[dict]) -> int:
    """Ingest Zeek conn.log records (JSON format).

    Returns count of records inserted.
    """
    inserted = 0
    with get_cursor() as cur:
        for raw in records:
            ts = _parse_timestamp(raw, "ts")
            cur.execute(
                """INSERT INTO records (case_id, record_type, source_plugin, raw, ts)
                   VALUES (%s, 'zeek_conn', 'sphinx-plugin-pcap', %s, %s)
                   RETURNING id""",
                (case_id, json.dumps(raw), ts),
            )
            record_id = cur.fetchone()["id"]
            extract_and_store(case_id, record_id, raw)
            inserted += 1
        cur.connection.commit()

    log.info("Ingested %d Zeek conn records for case %s", inserted, case_id)
    return inserted


def ingest_zeek_dns(case_id: str, records: list[dict]) -> int:
    """Ingest Zeek dns.log records (JSON format)."""
    inserted = 0
    with get_cursor() as cur:
        for raw in records:
            ts = _parse_timestamp(raw, "ts")
            cur.execute(
                """INSERT INTO records (case_id, record_type, source_plugin, raw, ts)
                   VALUES (%s, 'zeek_dns', 'sphinx-plugin-pcap', %s, %s)
                   RETURNING id""",
                (case_id, json.dumps(raw), ts),
            )
            record_id = cur.fetchone()["id"]
            extract_and_store(case_id, record_id, raw)
            inserted += 1
        cur.connection.commit()

    log.info("Ingested %d Zeek DNS records for case %s", inserted, case_id)
    return inserted


def ingest_tshark(case_id: str, records: list[dict]) -> int:
    """Ingest tshark TCP stream reconstruction output."""
    inserted = 0
    with get_cursor() as cur:
        for raw in records:
            ts = _parse_timestamp(raw, "timestamp", "ts")
            cur.execute(
                """INSERT INTO records (case_id, record_type, source_plugin, raw, ts)
                   VALUES (%s, 'tshark_stream', 'sphinx-plugin-pcap', %s, %s)
                   RETURNING id""",
                (case_id, json.dumps(raw), ts),
            )
            record_id = cur.fetchone()["id"]
            extract_and_store(case_id, record_id, raw)
            inserted += 1
        cur.connection.commit()

    log.info("Ingested %d tshark stream records for case %s", inserted, case_id)
    return inserted