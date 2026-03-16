"""Threat Hunter precompute — cross-source correlation analytics."""

from __future__ import annotations

from typing import Any

from sphinx.plugins.sphinx_plugin_threat_hunter.mitre import detect_techniques


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


def mitre_detections(case_id: str, cur) -> dict[str, Any]:
    """Run pattern-based MITRE ATT&CK detection against case evidence.

    Scans all records for known technique indicators and returns
    detected techniques with supporting record IDs.
    """
    detected = detect_techniques(case_id, cur)
    return {
        "name": "mitre_detections",
        "plugin": "sphinx-plugin-threat-hunter",
        "data": detected,
    }


# ---------------------------------------------------------------------------
# Cross-case precompute functions (correlator mode)
# These take a list of case_ids, not a single case_id.
# ---------------------------------------------------------------------------

def cross_case_shared_iocs(case_ids: list[str], cur) -> dict[str, Any]:
    """Find IOCs (IPs, domains, hashes, emails) that appear in 2+ cases."""
    cur.execute(
        """SELECT
               e.entity_type,
               e.value,
               array_agg(DISTINCT e.case_id) AS cases,
               count(DISTINCT e.case_id) AS case_count,
               count(*) AS total_refs
           FROM entities e
           WHERE e.case_id = ANY(%s)
             AND e.entity_type IN ('ip', 'domain', 'email', 'hash_md5', 'hash_sha1', 'hash_sha256', 'url')
           GROUP BY e.entity_type, e.value
           HAVING count(DISTINCT e.case_id) > 1
           ORDER BY case_count DESC, total_refs DESC
           LIMIT 50""",
        (case_ids,),
    )
    return {
        "name": "cross_case_shared_iocs",
        "plugin": "sphinx-plugin-threat-hunter",
        "data": cur.fetchall(),
    }


def cross_case_shared_signatures(case_ids: list[str], cur) -> dict[str, Any]:
    """Find Suricata alert signatures that triggered in 2+ cases."""
    cur.execute(
        """SELECT
               raw->>'alert'->>'signature' AS signature,
               raw->'alert'->>'signature_id' AS sid,
               raw->'alert'->>'category' AS category,
               array_agg(DISTINCT case_id) AS cases,
               count(DISTINCT case_id) AS case_count,
               count(*) AS total_hits
           FROM records
           WHERE case_id = ANY(%s)
             AND record_type = 'suricata_alert'
             AND raw->'alert'->>'signature' IS NOT NULL
           GROUP BY signature, sid, category
           HAVING count(DISTINCT case_id) > 1
           ORDER BY case_count DESC, total_hits DESC
           LIMIT 30""",
        (case_ids,),
    )
    return {
        "name": "cross_case_shared_signatures",
        "plugin": "sphinx-plugin-threat-hunter",
        "data": cur.fetchall(),
    }


def cross_case_shared_destinations(case_ids: list[str], cur) -> dict[str, Any]:
    """Find external destination IP:port pairs contacted from 2+ cases."""
    cur.execute(
        """SELECT
               raw->>'dest_ip' AS dst_ip,
               raw->>'dest_port' AS dst_port,
               COALESCE(raw->>'app_proto', '') AS service,
               array_agg(DISTINCT case_id) AS cases,
               count(DISTINCT case_id) AS case_count,
               count(*) AS total_conns
           FROM records
           WHERE case_id = ANY(%s)
             AND record_type IN ('suricata_alert', 'suricata_flow', 'zeek_conn')
             AND raw->>'dest_ip' IS NOT NULL
           GROUP BY dst_ip, dst_port, service
           HAVING count(DISTINCT case_id) > 1
           ORDER BY case_count DESC, total_conns DESC
           LIMIT 30""",
        (case_ids,),
    )
    return {
        "name": "cross_case_shared_destinations",
        "plugin": "sphinx-plugin-threat-hunter",
        "data": cur.fetchall(),
    }


def cross_case_mitre_overlap(case_ids: list[str], cur) -> dict[str, Any]:
    """Find MITRE ATT&CK techniques detected in 2+ cases."""
    # Run detection per case, then find overlap
    from sphinx.plugins.sphinx_plugin_threat_hunter.mitre import detect_techniques

    technique_cases: dict[str, dict] = {}  # technique_id -> {info, cases, evidence}

    for cid in case_ids:
        detected = detect_techniques(cid, cur)
        for d in detected:
            tid = d["technique_id"]
            if tid not in technique_cases:
                technique_cases[tid] = {
                    "technique_id": tid,
                    "technique_name": d["technique_name"],
                    "tactic": d["tactic"],
                    "cases": [],
                    "sample_records": {},
                }
            technique_cases[tid]["cases"].append(cid)
            technique_cases[tid]["sample_records"][cid] = d.get("sample_record_ids", [])[:5]

    # Filter to techniques in 2+ cases
    shared = [v for v in technique_cases.values() if len(v["cases"]) > 1]
    shared.sort(key=lambda x: len(x["cases"]), reverse=True)

    return {
        "name": "cross_case_mitre_overlap",
        "plugin": "sphinx-plugin-threat-hunter",
        "data": shared,
    }


# Registry of cross-case functions (used by precompute.py)
CROSS_CASE_PRECOMPUTE_FNS = [
    cross_case_shared_iocs,
    cross_case_shared_signatures,
    cross_case_shared_destinations,
    cross_case_mitre_overlap,
]