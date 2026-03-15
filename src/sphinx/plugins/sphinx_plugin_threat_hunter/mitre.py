"""Threat Hunter MITRE ATT&CK mapping — technique detection patterns."""

from __future__ import annotations

from typing import Any

# Common technique detection rules (pattern-based, no LLM needed)
# Covers both Windows and Linux attack patterns.
TECHNIQUE_PATTERNS = {
    # ── Execution ──
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
    "T1059.004": {
        "name": "Unix Shell",
        "tactic": "Execution",
        "indicators": {
            "keywords": ["/bin/bash", "/bin/sh", "bash -c", "sh -c"],
        },
    },
    # ── Persistence ──
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Persistence, Defense Evasion",
        "indicators": {
            "record_types": ["win_evt_security"],
            "event_ids": [4624, 4648],
        },
    },
    "T1543.002": {
        "name": "Systemd Service",
        "tactic": "Persistence, Privilege Escalation",
        "indicators": {
            "keywords": ["systemctl", ".service", "/etc/systemd"],
        },
    },
    # ── Defense Evasion ──
    "T1070.002": {
        "name": "Clear Linux or Mac System Logs",
        "tactic": "Defense Evasion",
        "indicators": {
            "keywords": ["unset HISTFILE", "HISTFILESIZE=0", "history -c",
                         "export HISTSIZE=0", "set +o history"],
        },
    },
    "T1070.003": {
        "name": "Clear Command History",
        "tactic": "Defense Evasion",
        "indicators": {
            "keywords": ["rm .bash_history", "rm .zsh_history",
                         "> .bash_history", "cat /dev/null >"],
        },
    },
    "T1070.004": {
        "name": "File Deletion",
        "tactic": "Defense Evasion",
        "indicators": {
            "keywords": ["rm -f", "rm -rf", "shred", "wipe"],
        },
    },
    "T1070.006": {
        "name": "Timestomp",
        "tactic": "Defense Evasion",
        "indicators": {
            "keywords": ["touch -r", "touch -t", "touch -d",
                         "SetFileTime", "timestomp"],
        },
    },
    "T1070.009": {
        "name": "Clear Persistence",
        "tactic": "Defense Evasion",
        "indicators": {
            "keywords": ["sed -i", "sed -e", "/var/log"],
        },
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "indicators": {
            "keywords": ["base64 --decode", "base64 -d", "openssl enc",
                         "python -c", "perl -e"],
        },
    },
    "T1036.005": {
        "name": "Match Legitimate Name or Location",
        "tactic": "Defense Evasion",
        "indicators": {
            "keywords": ["/usr/bin/", "/usr/sbin/", "/usr/local/bin/"],
        },
    },
    # ── Lateral Movement ──
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
    "T1021.004": {
        "name": "SSH",
        "tactic": "Lateral Movement",
        "indicators": {
            "keywords": ["scp ", "ssh ", "sftp "],
            "ports": [22],
        },
    },
    # ── Collection / Exfiltration ──
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "indicators": {
            "keywords": ["exfil", "upload", "compress", "archive"],
        },
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "indicators": {
            "keywords": ["scp -P", "curl -X POST", "wget --post",
                         "nc ", "ncat "],
        },
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "indicators": {
            "keywords": ["wget ", "curl ", "scp ", "tftp",
                         "certutil -urlcache", "bitsadmin"],
        },
    },
    # ── Privilege Escalation ──
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "indicators": {
            "record_types": ["vol_malfind"],
        },
    },
    # ── Command and Control ──
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "indicators": {
            "protocols": ["http", "https"],
            "app_protos": ["http", "tls"],
        },
    },
    "T1571": {
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "indicators": {
            "keywords": ["scp -P", "ssh -p"],
        },
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactic": "Command and Control",
        "indicators": {
            "keywords": ["socks", "tunnel", "proxy", "ssh -D", "ssh -R"],
        },
    },
    # ── Credential Access ──
    "T1552.001": {
        "name": "Credentials In Files",
        "tactic": "Credential Access",
        "indicators": {
            "keywords": [".ssh/id_rsa", ".ssh/authorized_keys",
                         "/etc/shadow", "passwd"],
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