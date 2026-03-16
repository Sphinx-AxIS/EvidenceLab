"""PCAP plugin precompute — standard analytics run before RLM loop."""

from __future__ import annotations

import json
from typing import Any


def top_talkers(case_id: str, cur) -> dict[str, Any]:
    """Top source/destination IP pairs by record count."""
    cur.execute(
        """SELECT
               raw->>'src_ip' AS src_ip,
               raw->>'dest_ip' AS dst_ip,
               count(*) AS cnt
           FROM records
           WHERE case_id = %s
             AND record_type IN ('suricata_alert', 'zeek_conn')
             AND raw->>'src_ip' IS NOT NULL
           GROUP BY src_ip, dst_ip
           ORDER BY cnt DESC
           LIMIT 25""",
        (case_id,),
    )
    rows = cur.fetchall()
    return {
        "name": "top_talkers",
        "plugin": "sphinx-plugin-pcap",
        "data": rows,
    }


def alert_severity_counts(case_id: str, cur) -> dict[str, Any]:
    """Suricata alert counts grouped by severity level."""
    cur.execute(
        """SELECT
               (raw->'alert'->>'severity')::int AS severity,
               raw->'alert'->>'category' AS category,
               count(*) AS cnt
           FROM records
           WHERE case_id = %s
             AND record_type = 'suricata_alert'
           GROUP BY severity, category
           ORDER BY severity, cnt DESC""",
        (case_id,),
    )
    rows = cur.fetchall()
    return {
        "name": "alert_severity_counts",
        "plugin": "sphinx-plugin-pcap",
        "data": rows,
    }


def protocol_distribution(case_id: str, cur) -> dict[str, Any]:
    """Protocol breakdown across network records."""
    cur.execute(
        """SELECT
               COALESCE(raw->>'proto', raw->>'protocol', 'unknown') AS protocol,
               COALESCE(raw->>'app_proto', raw->>'service', '') AS app_proto,
               count(*) AS cnt
           FROM records
           WHERE case_id = %s
             AND record_type IN ('suricata_alert', 'zeek_conn')
           GROUP BY protocol, app_proto
           ORDER BY cnt DESC""",
        (case_id,),
    )
    rows = cur.fetchall()
    return {
        "name": "protocol_distribution",
        "plugin": "sphinx-plugin-pcap",
        "data": rows,
    }


def connection_timeline(case_id: str, cur) -> dict[str, Any]:
    """Network connections bucketed by hour."""
    cur.execute(
        """SELECT
               date_trunc('hour', ts) AS hour,
               record_type,
               count(*) AS cnt
           FROM records
           WHERE case_id = %s
             AND record_type IN ('suricata_alert', 'zeek_conn')
             AND ts IS NOT NULL
           GROUP BY hour, record_type
           ORDER BY hour""",
        (case_id,),
    )
    rows = cur.fetchall()
    # Convert datetimes to strings for JSON serialization
    for row in rows:
        if row.get("hour"):
            row["hour"] = row["hour"].isoformat()
    return {
        "name": "connection_timeline",
        "plugin": "sphinx-plugin-pcap",
        "data": rows,
    }