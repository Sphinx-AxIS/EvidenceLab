"""WinEVT plugin precompute — standard analytics for Windows events."""

from __future__ import annotations

from typing import Any


def logon_summary(case_id: str, cur) -> dict[str, Any]:
    """Logon event summary (EventID 4624/4625) by type and account."""
    cur.execute(
        """SELECT
               (raw->>'EventID')::int AS event_id,
               (raw->'EventData'->>'LogonType')::int AS logon_type,
               raw->'EventData'->>'TargetUserName' AS target_user,
               count(*) AS cnt
           FROM records
           WHERE case_id = %s
             AND record_type = 'win_evt_security'
             AND (raw->>'EventID')::int IN (4624, 4625)
           GROUP BY event_id, logon_type, target_user
           ORDER BY cnt DESC
           LIMIT 25""",
        (case_id,),
    )
    return {
        "name": "logon_summary",
        "plugin": "sphinx-plugin-winevt",
        "data": cur.fetchall(),
    }


def event_id_counts(case_id: str, cur) -> dict[str, Any]:
    """Event ID distribution across all Windows event channels."""
    cur.execute(
        """SELECT
               record_type,
               (raw->>'EventID')::int AS event_id,
               count(*) AS cnt
           FROM records
           WHERE case_id = %s
             AND record_type LIKE 'win_evt_%%'
           GROUP BY record_type, event_id
           ORDER BY cnt DESC
           LIMIT 50""",
        (case_id,),
    )
    return {
        "name": "event_id_counts",
        "plugin": "sphinx-plugin-winevt",
        "data": cur.fetchall(),
    }


def powershell_commands(case_id: str, cur) -> dict[str, Any]:
    """Extract PowerShell script block text from EventID 4104."""
    cur.execute(
        """SELECT
               r.id AS record_id,
               r.ts,
               r.raw->'EventData'->>'ScriptBlockText' AS script_text
           FROM records r
           WHERE r.case_id = %s
             AND r.record_type = 'win_evt_powershell'
             AND (r.raw->>'EventID')::int = 4104
           ORDER BY r.ts
           LIMIT 100""",
        (case_id,),
    )
    rows = cur.fetchall()
    # Truncate long scripts for precompute summary
    for row in rows:
        if row.get("script_text") and len(row["script_text"]) > 500:
            row["script_text"] = row["script_text"][:500] + "..."
    return {
        "name": "powershell_commands",
        "plugin": "sphinx-plugin-winevt",
        "data": rows,
    }


def process_creation_summary(case_id: str, cur) -> dict[str, Any]:
    """Sysmon Event ID 1 (Process Creation) summary."""
    cur.execute(
        """SELECT
               raw->'EventData'->>'Image' AS image,
               raw->'EventData'->>'ParentImage' AS parent_image,
               count(*) AS cnt
           FROM records
           WHERE case_id = %s
             AND record_type = 'win_evt_sysmon'
             AND (raw->>'EventID')::int = 1
           GROUP BY image, parent_image
           ORDER BY cnt DESC
           LIMIT 30""",
        (case_id,),
    )
    return {
        "name": "process_creation_summary",
        "plugin": "sphinx-plugin-winevt",
        "data": cur.fetchall(),
    }