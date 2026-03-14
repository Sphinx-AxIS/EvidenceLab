-- PCAP plugin migration: net_events OCSF view
-- This view extracts flat columns from Suricata and Zeek JSONB records.

CREATE OR REPLACE VIEW net_events AS
SELECT
    r.id AS record_id,
    r.case_id,
    r.record_type,
    r.ts,
    r.raw->>'src_ip' AS src_ip,
    (r.raw->>'src_port')::int AS src_port,
    r.raw->>'dest_ip' AS dst_ip,
    (r.raw->>'dest_port')::int AS dst_port,
    COALESCE(r.raw->>'proto', r.raw->>'protocol') AS protocol,
    r.raw->'alert'->>'signature' AS alert_signature,
    (r.raw->'alert'->>'severity')::int AS alert_severity,
    r.raw->'alert'->>'category' AS alert_category,
    (r.raw->'alert'->>'signature_id')::int AS alert_sid,
    r.raw->>'uid' AS zeek_uid,
    r.raw->>'service' AS service,
    (r.raw->>'duration')::numeric AS duration,
    (r.raw->>'orig_bytes')::bigint AS orig_bytes,
    (r.raw->>'resp_bytes')::bigint AS resp_bytes,
    r.raw->>'conn_state' AS conn_state,
    r.raw->>'community_id' AS community_id,
    r.raw->>'app_proto' AS app_proto
FROM records r
WHERE r.record_type IN ('suricata_alert', 'zeek_conn');