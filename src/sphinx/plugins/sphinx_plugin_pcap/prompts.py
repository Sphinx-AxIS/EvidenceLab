"""PCAP plugin prompts — LLM instructions for network evidence analysis."""

SYSTEM_PROMPT = """\
## Network Evidence (PCAP Plugin)

This case contains network traffic evidence from one or more of:
- **Suricata alerts** (record_type: suricata_alert) — IDS alert records
- **Zeek conn logs** (record_type: zeek_conn) — connection metadata
- **Zeek DNS logs** (record_type: zeek_dns) — DNS query/response records
- **tshark streams** (record_type: tshark_stream) — TCP stream reconstructions

### Suricata Alert Fields
Top-level: `raw->>'src_ip'`, `raw->>'dest_ip'`, `raw->>'proto'`, `raw->>'timestamp'`
Nested alert fields (use `->` then `->>` for the leaf):
- `raw->'alert'->>'signature'` — rule name that triggered
- `raw->'alert'->>'severity'` — 1=high, 2=medium, 3=low
- `raw->'alert'->>'category'` — alert category
- `raw->'alert'->>'signature_id'` — rule SID
Other: `raw->>'app_proto'`, `raw->>'community_id'`

### Zeek Conn Fields
Nested ID fields (use `->` then `->>` for the leaf):
- `raw->'id'->>'orig_h'`, `raw->'id'->>'orig_p'` — source IP/port
- `raw->'id'->>'resp_h'`, `raw->'id'->>'resp_p'` — dest IP/port
Top-level: `raw->>'uid'`, `raw->>'proto'`, `raw->>'service'`, `raw->>'duration'`
- `raw->>'orig_bytes'`, `raw->>'resp_bytes'`, `raw->>'conn_state'`
- `raw->>'community_id'`

### Query Tips
- Filter by case_id AND record_type in every query
- Top-level fields: `raw->>'field_name'`
- Nested fields: `raw->'parent'->>'child'` (use `->` for intermediate, `->>` for leaf)
- Numeric cast: `(raw->>'field')::int`
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