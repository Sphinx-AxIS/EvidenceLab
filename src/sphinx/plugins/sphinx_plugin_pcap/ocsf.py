"""PCAP plugin OCSF mapper — flat-column network event view."""

from __future__ import annotations

import logging

from sphinx.core.db import get_cursor

log = logging.getLogger(__name__)


def map_net_events(case_id: str) -> int:
    """Create/refresh the net_events OCSF view for a case.

    Extracts flat columns from Suricata and Zeek raw JSONB into a
    queryable view. Returns row count.
    """
    with get_cursor() as cur:
        # Create materialized view (or refresh if exists)
        cur.execute(
            """CREATE OR REPLACE VIEW net_events AS
               SELECT
                   r.id AS record_id,
                   r.case_id,
                   r.record_type,
                   r.ts,
                   -- Network 5-tuple
                   r.raw->>'src_ip' AS src_ip,
                   (r.raw->>'src_port')::int AS src_port,
                   r.raw->>'dest_ip' AS dst_ip,
                   (r.raw->>'dest_port')::int AS dst_port,
                   COALESCE(r.raw->>'proto', r.raw->>'protocol') AS protocol,
                   -- Suricata alert fields
                   r.raw->'alert'->>'signature' AS alert_signature,
                   (r.raw->'alert'->>'severity')::int AS alert_severity,
                   r.raw->'alert'->>'category' AS alert_category,
                   (r.raw->'alert'->>'signature_id')::int AS alert_sid,
                   -- Zeek conn fields
                   r.raw->>'uid' AS zeek_uid,
                   r.raw->>'service' AS service,
                   (r.raw->>'duration')::numeric AS duration,
                   (r.raw->>'orig_bytes')::bigint AS orig_bytes,
                   (r.raw->>'resp_bytes')::bigint AS resp_bytes,
                   r.raw->>'conn_state' AS conn_state,
                   -- Flow metadata
                   r.raw->>'community_id' AS community_id,
                   r.raw->>'app_proto' AS app_proto
               FROM records r
               WHERE r.record_type IN ('suricata_alert', 'zeek_conn')"""
        )
        cur.connection.commit()

        # Count rows for this case
        cur.execute(
            "SELECT count(*) AS cnt FROM net_events WHERE case_id = %s",
            (case_id,),
        )
        count = cur.fetchone()["cnt"]

    log.info("OCSF net_events view: %d rows for case %s", count, case_id)
    return count