"""Memory plugin ingest — parsers for Volatility 3 JSON output."""

from __future__ import annotations

import json
import logging
from typing import Any

from sphinx.core.db import get_cursor
from sphinx.core.entity_extractor import extract_and_store

log = logging.getLogger(__name__)


def _ingest_vol(case_id: str, record_type: str, records: list[dict]) -> int:
    """Generic ingest for Volatility 3 JSON output."""
    inserted = 0
    with get_cursor() as cur:
        for raw in records:
            cur.execute(
                """INSERT INTO records (case_id, record_type, source_plugin, raw)
                   VALUES (%s, %s, 'sphinx-plugin-memory', %s)
                   RETURNING id""",
                (case_id, record_type, json.dumps(raw)),
            )
            record_id = cur.fetchone()["id"]
            extract_and_store(case_id, record_id, raw)
            inserted += 1
        cur.connection.commit()

    log.info("Ingested %d %s records for case %s", inserted, record_type, case_id)
    return inserted


def ingest_pslist(case_id: str, records: list[dict]) -> int:
    return _ingest_vol(case_id, "vol_pslist", records)

def ingest_netscan(case_id: str, records: list[dict]) -> int:
    return _ingest_vol(case_id, "vol_netscan", records)

def ingest_cmdline(case_id: str, records: list[dict]) -> int:
    return _ingest_vol(case_id, "vol_cmdline", records)

def ingest_dlllist(case_id: str, records: list[dict]) -> int:
    return _ingest_vol(case_id, "vol_dlllist", records)

def ingest_handles(case_id: str, records: list[dict]) -> int:
    return _ingest_vol(case_id, "vol_handles", records)

def ingest_malfind(case_id: str, records: list[dict]) -> int:
    return _ingest_vol(case_id, "vol_malfind", records)