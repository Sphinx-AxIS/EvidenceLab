"""Memory plugin precompute — standard analytics for memory forensics."""

from __future__ import annotations

from typing import Any


def process_tree(case_id: str, cur) -> dict[str, Any]:
    """Process list with parent-child relationships."""
    cur.execute(
        """SELECT
               raw->>'PID' AS pid,
               raw->>'PPID' AS ppid,
               raw->>'ImageFileName' AS name,
               raw->>'CreateTime' AS create_time,
               raw->>'ExitTime' AS exit_time
           FROM records
           WHERE case_id = %s AND record_type = 'vol_pslist'
           ORDER BY (raw->>'PID')::int""",
        (case_id,),
    )
    return {
        "name": "process_tree",
        "plugin": "sphinx-plugin-memory",
        "data": cur.fetchall(),
    }


def network_connections(case_id: str, cur) -> dict[str, Any]:
    """Network connections from memory (netscan)."""
    cur.execute(
        """SELECT
               raw->>'LocalAddr' AS local_addr,
               raw->>'LocalPort' AS local_port,
               raw->>'ForeignAddr' AS foreign_addr,
               raw->>'ForeignPort' AS foreign_port,
               raw->>'State' AS state,
               raw->>'Owner' AS owner,
               raw->>'PID' AS pid,
               raw->>'Proto' AS proto
           FROM records
           WHERE case_id = %s AND record_type = 'vol_netscan'
           ORDER BY (raw->>'PID')::int""",
        (case_id,),
    )
    return {
        "name": "network_connections",
        "plugin": "sphinx-plugin-memory",
        "data": cur.fetchall(),
    }


def suspicious_processes(case_id: str, cur) -> dict[str, Any]:
    """Malfind results — processes with suspicious memory regions."""
    cur.execute(
        """SELECT
               raw->>'PID' AS pid,
               raw->>'Process' AS process,
               raw->>'Start VPN' AS start_vpn,
               raw->>'End VPN' AS end_vpn,
               raw->>'Protection' AS protection,
               raw->>'Hexdump' AS hexdump
           FROM records
           WHERE case_id = %s AND record_type = 'vol_malfind'
           ORDER BY (raw->>'PID')::int""",
        (case_id,),
    )
    rows = cur.fetchall()
    for row in rows:
        if row.get("hexdump") and len(row["hexdump"]) > 200:
            row["hexdump"] = row["hexdump"][:200] + "..."
    return {
        "name": "suspicious_processes",
        "plugin": "sphinx-plugin-memory",
        "data": rows,
    }