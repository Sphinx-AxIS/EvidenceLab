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
            extract_and_store(case_id, record_id, raw, cur=cur)
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
            extract_and_store(case_id, record_id, raw, cur=cur)
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
            extract_and_store(case_id, record_id, raw, cur=cur)
            inserted += 1
        cur.connection.commit()

    log.info("Ingested %d Zeek DNS records for case %s", inserted, case_id)
    return inserted


def ingest_tshark(case_id: str, records: list[dict]) -> int:
    """Ingest tshark TCP stream reconstruction output."""
    inserted = 0
    with get_cursor() as cur:
        for raw in records:
            ts = _parse_timestamp(raw, "timestamp", "ts", "first_ts")
            cur.execute(
                """INSERT INTO records (case_id, record_type, source_plugin, raw, ts)
                   VALUES (%s, 'tshark_stream', 'sphinx-plugin-pcap', %s, %s)
                   RETURNING id""",
                (case_id, json.dumps(raw), ts),
            )
            record_id = cur.fetchone()["id"]
            extract_and_store(case_id, record_id, raw, cur=cur)
            inserted += 1
        cur.connection.commit()

    log.info("Ingested %d tshark stream records for case %s", inserted, case_id)
    return inserted


# ---------------------------------------------------------------------------
# Generic handlers — used by convert.py for all Suricata/Zeek types
# ---------------------------------------------------------------------------

def ingest_suricata_records(case_id: str, records: list[dict], record_type: str) -> int:
    """Ingest Suricata EVE JSON records of any event type.

    Args:
        case_id: Case UUID.
        records: List of EVE JSON dicts.
        record_type: e.g. 'suricata_alert', 'suricata_http', 'suricata_dns'.
    """
    inserted = 0
    with get_cursor() as cur:
        for raw in records:
            ts = _parse_timestamp(raw, "timestamp")
            cur.execute(
                """INSERT INTO records (case_id, record_type, source_plugin, raw, ts)
                   VALUES (%s, %s, 'sphinx-plugin-pcap', %s, %s)
                   RETURNING id""",
                (case_id, record_type, json.dumps(raw), ts),
            )
            record_id = cur.fetchone()["id"]
            extract_and_store(case_id, record_id, raw, cur=cur)
            inserted += 1
        cur.connection.commit()

    log.info("Ingested %d %s records for case %s", inserted, record_type, case_id)
    return inserted


def ingest_zeek_records(case_id: str, records: list[dict], record_type: str) -> int:
    """Ingest Zeek log records of any type.

    Args:
        case_id: Case UUID.
        records: List of parsed Zeek JSON log entries.
        record_type: e.g. 'zeek_conn', 'zeek_dns', 'zeek_http'.
    """
    inserted = 0
    with get_cursor() as cur:
        for raw in records:
            ts = _parse_timestamp(raw, "ts")
            cur.execute(
                """INSERT INTO records (case_id, record_type, source_plugin, raw, ts)
                   VALUES (%s, %s, 'sphinx-plugin-pcap', %s, %s)
                   RETURNING id""",
                (case_id, record_type, json.dumps(raw), ts),
            )
            record_id = cur.fetchone()["id"]
            extract_and_store(case_id, record_id, raw, cur=cur)
            inserted += 1
        cur.connection.commit()

    log.info("Ingested %d %s records for case %s", inserted, record_type, case_id)
    return inserted


# Convenience wrappers for manifest handler registration (all Suricata types)

def ingest_suricata_http(case_id: str, records: list[dict]) -> int:
    return ingest_suricata_records(case_id, records, "suricata_http")

def ingest_suricata_dns(case_id: str, records: list[dict]) -> int:
    return ingest_suricata_records(case_id, records, "suricata_dns")

def ingest_suricata_tls(case_id: str, records: list[dict]) -> int:
    return ingest_suricata_records(case_id, records, "suricata_tls")

def ingest_suricata_fileinfo(case_id: str, records: list[dict]) -> int:
    return ingest_suricata_records(case_id, records, "suricata_fileinfo")

def ingest_suricata_flow(case_id: str, records: list[dict]) -> int:
    return ingest_suricata_records(case_id, records, "suricata_flow")

def ingest_suricata_smtp(case_id: str, records: list[dict]) -> int:
    return ingest_suricata_records(case_id, records, "suricata_smtp")

def ingest_suricata_ssh(case_id: str, records: list[dict]) -> int:
    return ingest_suricata_records(case_id, records, "suricata_ssh")


# Convenience wrappers for manifest handler registration (all Zeek types)

def ingest_zeek_http(case_id: str, records: list[dict]) -> int:
    return ingest_zeek_records(case_id, records, "zeek_http")

def ingest_zeek_ssl(case_id: str, records: list[dict]) -> int:
    return ingest_zeek_records(case_id, records, "zeek_ssl")

def ingest_zeek_files(case_id: str, records: list[dict]) -> int:
    return ingest_zeek_records(case_id, records, "zeek_files")

def ingest_zeek_x509(case_id: str, records: list[dict]) -> int:
    return ingest_zeek_records(case_id, records, "zeek_x509")

def ingest_zeek_notice(case_id: str, records: list[dict]) -> int:
    return ingest_zeek_records(case_id, records, "zeek_notice")

def ingest_zeek_weird(case_id: str, records: list[dict]) -> int:
    return ingest_zeek_records(case_id, records, "zeek_weird")

def ingest_zeek_dhcp(case_id: str, records: list[dict]) -> int:
    return ingest_zeek_records(case_id, records, "zeek_dhcp")

def ingest_zeek_smtp(case_id: str, records: list[dict]) -> int:
    return ingest_zeek_records(case_id, records, "zeek_smtp")

def ingest_zeek_ssh(case_id: str, records: list[dict]) -> int:
    return ingest_zeek_records(case_id, records, "zeek_ssh")

def ingest_zeek_rdp(case_id: str, records: list[dict]) -> int:
    return ingest_zeek_records(case_id, records, "zeek_rdp")

def ingest_zeek_pe(case_id: str, records: list[dict]) -> int:
    return ingest_zeek_records(case_id, records, "zeek_pe")

def ingest_zeek_dpd(case_id: str, records: list[dict]) -> int:
    return ingest_zeek_records(case_id, records, "zeek_dpd")

def ingest_zeek_ntp(case_id: str, records: list[dict]) -> int:
    return ingest_zeek_records(case_id, records, "zeek_ntp")

def ingest_zeek_software(case_id: str, records: list[dict]) -> int:
    return ingest_zeek_records(case_id, records, "zeek_software")