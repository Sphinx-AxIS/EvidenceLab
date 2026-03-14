"""PCAP plugin manifest — Suricata alerts, Zeek logs, tshark streams."""

MANIFEST = {
    "name": "sphinx-plugin-pcap",
    "version": "0.1.0",
    "description": "PCAP evidence: Suricata alerts, Zeek connection logs, tshark TCP streams",

    "ingest_handlers": {
        "suricata_alert": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_suricata",
        "zeek_conn": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_conn",
        "zeek_dns": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_dns",
        "tshark_stream": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_tshark",
    },

    "ocsf_mappers": {
        "net_events": "sphinx.plugins.sphinx_plugin_pcap.ocsf:map_net_events",
    },

    "prompts": {
        "pcap_system": "sphinx.plugins.sphinx_plugin_pcap.prompts:SYSTEM_PROMPT",
        "pcap_docs": "sphinx.plugins.sphinx_plugin_pcap.prompts:DOC_SECTIONS",
    },

    "precompute": [
        "sphinx.plugins.sphinx_plugin_pcap.precompute:top_talkers",
        "sphinx.plugins.sphinx_plugin_pcap.precompute:alert_severity_counts",
        "sphinx.plugins.sphinx_plugin_pcap.precompute:protocol_distribution",
        "sphinx.plugins.sphinx_plugin_pcap.precompute:connection_timeline",
    ],

    "migrations": [
        "sql/001_pcap_views.sql",
    ],

    "dashboard_widgets": [],
}