"""Threat Hunter correlator — programmatic cross-source analysis."""

from __future__ import annotations

import logging
from typing import Any

from sphinx.core.db import get_cursor

log = logging.getLogger(__name__)


def find_lateral_movement(case_id: str) -> list[dict[str, Any]]:
    """Detect potential lateral movement by correlating network + auth events.

    Looks for: remote logon events (type 3/10) followed by or preceded by
    network connections to the same host.
    """
    with get_cursor() as cur:
        # Find network logons with source IPs
        cur.execute(
            """SELECT
                   r.id AS record_id,
                   r.ts,
                   r.raw->'EventData'->>'IpAddress' AS source_ip,
                   r.raw->'EventData'->>'TargetUserName' AS user_name,
                   (r.raw->'EventData'->>'LogonType')::int AS logon_type
               FROM records r
               WHERE r.case_id = %s
                 AND r.record_type = 'win_evt_security'
                 AND (r.raw->>'EventID')::int = 4624
                 AND (r.raw->'EventData'->>'LogonType')::int IN (3, 10)
                 AND r.raw->'EventData'->>'IpAddress' IS NOT NULL
                 AND r.raw->'EventData'->>'IpAddress' != '-'
               ORDER BY r.ts""",
            (case_id,),
        )
        logons = cur.fetchall()

        if not logons:
            return []

        # Find matching network connections
        source_ips = list({l["source_ip"] for l in logons if l["source_ip"]})
        if not source_ips:
            return []

        cur.execute(
            """SELECT
                   r.id AS record_id,
                   r.ts,
                   r.raw->>'src_ip' AS src_ip,
                   r.raw->>'dest_ip' AS dest_ip,
                   r.raw->'alert'->>'signature' AS signature
               FROM records r
               WHERE r.case_id = %s
                 AND r.record_type IN ('suricata_alert', 'zeek_conn')
                 AND r.raw->>'src_ip' = ANY(%s)
               ORDER BY r.ts""",
            (case_id, source_ips),
        )
        connections = cur.fetchall()

    # Correlate
    results = []
    for logon in logons:
        related = [
            c for c in connections
            if c["src_ip"] == logon["source_ip"]
        ]
        if related:
            results.append({
                "logon_record": logon["record_id"],
                "timestamp": logon["ts"].isoformat() if logon["ts"] else None,
                "source_ip": logon["source_ip"],
                "user": logon["user_name"],
                "logon_type": logon["logon_type"],
                "related_network_records": [r["record_id"] for r in related],
                "signatures": [
                    r["signature"] for r in related if r.get("signature")
                ],
            })

    return results