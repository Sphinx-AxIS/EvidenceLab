"""WinEVT plugin OCSF mapper — authentication event view."""

from __future__ import annotations

import logging

from sphinx.core.db import get_cursor

log = logging.getLogger(__name__)


def map_auth_events(case_id: str) -> int:
    """Create/refresh the auth_events OCSF view."""
    with get_cursor() as cur:
        cur.execute(
            """CREATE OR REPLACE VIEW auth_events AS
               SELECT
                   r.id AS record_id,
                   r.case_id,
                   r.record_type,
                   r.ts,
                   -- Event identification
                   (r.raw->>'EventID')::int AS event_id,
                   r.raw->>'Channel' AS channel,
                   r.raw->>'Computer' AS computer,
                   -- Account info
                   r.raw->'EventData'->>'TargetUserName' AS target_user,
                   r.raw->'EventData'->>'TargetDomainName' AS target_domain,
                   r.raw->'EventData'->>'SubjectUserName' AS subject_user,
                   -- Logon details
                   (r.raw->'EventData'->>'LogonType')::int AS logon_type,
                   r.raw->'EventData'->>'IpAddress' AS source_ip,
                   r.raw->'EventData'->>'WorkstationName' AS workstation,
                   r.raw->'EventData'->>'LogonProcessName' AS logon_process,
                   r.raw->'EventData'->>'AuthenticationPackageName' AS auth_package,
                   -- Process info (Sysmon)
                   r.raw->'EventData'->>'Image' AS process_image,
                   r.raw->'EventData'->>'CommandLine' AS command_line,
                   r.raw->'EventData'->>'ParentImage' AS parent_image,
                   (r.raw->'EventData'->>'ProcessId')::int AS process_id
               FROM records r
               WHERE r.record_type IN (
                   'win_evt_security', 'win_evt_sysmon'
               )"""
        )
        cur.connection.commit()

        cur.execute(
            "SELECT count(*) AS cnt FROM auth_events WHERE case_id = %s",
            (case_id,),
        )
        count = cur.fetchone()["cnt"]

    log.info("OCSF auth_events view: %d rows for case %s", count, case_id)
    return count