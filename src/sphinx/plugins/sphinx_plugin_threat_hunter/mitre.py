"""Threat Hunter MITRE ATT&CK mapping — technique detection patterns."""

from __future__ import annotations

from typing import Any

# Common technique detection rules (pattern-based, no LLM needed)
TECHNIQUE_PATTERNS = {
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "indicators": {
            "record_types": ["win_evt_powershell"],
            "event_ids": [4104],
            "keywords": ["powershell", "invoke-expression", "iex", "downloadstring"],
        },
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "indicators": {
            "process_names": ["cmd.exe"],
            "keywords": ["cmd /c", "cmd.exe /c"],
        },
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Persistence, Defense Evasion",
        "indicators": {
            "record_types": ["win_evt_security"],
            "event_ids": [4624, 4648],
        },
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "indicators": {
            "logon_types": [10],
            "ports": [3389],
        },
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "indicators": {
            "logon_types": [3],
            "ports": [445, 139],
        },
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "indicators": {
            "record_types": ["vol_malfind"],
        },
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "indicators": {
            "protocols": ["http", "https"],
            "app_protos": ["http", "tls"],
        },
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactic": "Command and Control",
        "indicators": {
            "keywords": ["socks", "tunnel", "proxy", "ssh -D", "ssh -R"],
        },
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "indicators": {
            "keywords": ["exfil", "upload", "compress", "archive"],
        },
    },
}


def detect_techniques(case_id: str, cur) -> list[dict[str, Any]]:
    """Scan case evidence for known MITRE ATT&CK technique indicators.

    Returns list of detected techniques with supporting record IDs.
    """
    detected = []

    for technique_id, info in TECHNIQUE_PATTERNS.items():
        indicators = info["indicators"]
        record_ids = set()

        # Check by record type
        if "record_types" in indicators:
            for rt in indicators["record_types"]:
                cur.execute(
                    """SELECT id FROM records
                       WHERE case_id = %s AND record_type = %s
                       LIMIT 10""",
                    (case_id, rt),
                )
                record_ids.update(r["id"] for r in cur.fetchall())

        # Check by event ID
        if "event_ids" in indicators and record_ids:
            for eid in indicators["event_ids"]:
                cur.execute(
                    """SELECT id FROM records
                       WHERE case_id = %s
                         AND (raw->>'EventID')::int = %s
                       LIMIT 10""",
                    (case_id, eid),
                )
                record_ids.update(r["id"] for r in cur.fetchall())

        # Check by keyword in raw data
        if "keywords" in indicators:
            for keyword in indicators["keywords"]:
                cur.execute(
                    """SELECT id FROM records
                       WHERE case_id = %s
                         AND raw::text ILIKE %s
                       LIMIT 5""",
                    (case_id, f"%{keyword}%"),
                )
                record_ids.update(r["id"] for r in cur.fetchall())

        if record_ids:
            detected.append({
                "technique_id": technique_id,
                "technique_name": info["name"],
                "tactic": info["tactic"],
                "evidence_count": len(record_ids),
                "sample_record_ids": sorted(record_ids)[:10],
            })

    return detected