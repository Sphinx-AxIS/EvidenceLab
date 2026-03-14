"""Threat Hunter precompute — cross-source correlation analytics."""

from __future__ import annotations

from typing import Any


def ioc_summary(case_id: str, cur) -> dict[str, Any]:
    """Aggregate all extracted IOCs by type and frequency."""
    cur.execute(
        """SELECT
               entity_type,
               value,
               count(*) AS record_count
           FROM entities
           WHERE case_id = %s
           GROUP BY entity_type, value
           ORDER BY record_count DESC
           LIMIT 50""",
        (case_id,),
    )
    return {
        "name": "ioc_summary",
        "plugin": "sphinx-plugin-threat-hunter",
        "data": cur.fetchall(),
    }


def cross_source_ips(case_id: str, cur) -> dict[str, Any]:
    """IPs that appear across multiple evidence source types."""
    cur.execute(
        """SELECT
               e.value AS ip,
               array_agg(DISTINCT r.record_type) AS source_types,
               count(DISTINCT r.record_type) AS source_count,
               count(*) AS total_refs
           FROM entities e
           JOIN records r ON r.id = e.record_id
           WHERE e.case_id = %s
             AND e.entity_type = 'ip'
           GROUP BY e.value
           HAVING count(DISTINCT r.record_type) > 1
           ORDER BY source_count DESC, total_refs DESC
           LIMIT 30""",
        (case_id,),
    )
    return {
        "name": "cross_source_ips",
        "plugin": "sphinx-plugin-threat-hunter",
        "data": cur.fetchall(),
    }


def attack_surface(case_id: str, cur) -> dict[str, Any]:
    """Summary of unique external IPs, ports, and protocols seen."""
    cur.execute(
        """SELECT
               raw->>'dest_ip' AS dst_ip,
               (raw->>'dest_port')::int AS dst_port,
               COALESCE(raw->>'app_proto', raw->>'service', '') AS service,
               count(*) AS cnt
           FROM records
           WHERE case_id = %s
             AND record_type IN ('suricata_alert', 'zeek_conn')
             AND raw->>'dest_ip' IS NOT NULL
           GROUP BY dst_ip, dst_port, service
           ORDER BY cnt DESC
           LIMIT 30""",
        (case_id,),
    )
    return {
        "name": "attack_surface",
        "plugin": "sphinx-plugin-threat-hunter",
        "data": cur.fetchall(),
    }