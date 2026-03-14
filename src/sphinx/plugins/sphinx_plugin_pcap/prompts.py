"""PCAP plugin prompts — LLM instructions for network evidence analysis."""

SYSTEM_PROMPT = """\
## Network Evidence (PCAP Plugin)

This case contains network traffic evidence from one or more of:
- **Suricata alerts** (record_type: suricata_alert) — IDS alert records
- **Zeek conn logs** (record_type: zeek_conn) — connection metadata
- **Zeek DNS logs** (record_type: zeek_dns) — DNS query/response records
- **tshark streams** (record_type: tshark_stream) — TCP stream reconstructions

### Suricata Alert Fields
Key fields in raw JSONB:
- src_ip, src_port, dest_ip, dest_port, proto
- alert.signature, alert.severity (1=high, 2=medium, 3=low), alert.category
- alert.signature_id, alert.action
- app_proto (http, tls, dns, ssh, etc.)
- community_id (flow correlation)

### Zeek Conn Fields
- id.orig_h, id.orig_p, id.resp_h, id.resp_p (or src_ip/dest_ip format)
- uid (unique connection ID), proto, service, duration
- orig_bytes, resp_bytes, conn_state
- community_id

### Query Tips
- Use `sql()` for direct SQL against the records table
- Filter by case_id AND record_type in every query
- Use `raw->>'field_name'` for JSONB text extraction
- Use `(raw->>'field_name')::int` for numeric casting
- Use `raw->'nested'->'field'` for nested JSONB access
- The net_events OCSF view provides flat columns if available
- Check `get_precomputed('top_talkers')` before writing your own aggregation
"""

DOC_SECTIONS = {
    "suricata": (
        "Suricata EVE JSON alert format. Key fields: timestamp, src_ip, "
        "dest_ip, src_port, dest_port, proto, alert.signature, "
        "alert.severity (1=high), alert.category, alert.signature_id, "
        "app_proto, community_id. Filter: record_type = 'suricata_alert'."
    ),
    "zeek_conn": (
        "Zeek conn.log JSON format. Key fields: ts, uid, id.orig_h, "
        "id.orig_p, id.resp_h, id.resp_p, proto, service, duration, "
        "orig_bytes, resp_bytes, conn_state. Filter: record_type = 'zeek_conn'."
    ),
    "zeek_dns": (
        "Zeek dns.log JSON format. Key fields: ts, uid, id.orig_h, "
        "id.resp_h, query, qtype, rcode, answers. "
        "Filter: record_type = 'zeek_dns'."
    ),
    "tshark": (
        "tshark TCP stream reconstruction. Contains reassembled payload "
        "data from TCP streams. Check for command execution, data "
        "exfiltration, C2 communication patterns. "
        "Filter: record_type = 'tshark_stream'."
    ),
}