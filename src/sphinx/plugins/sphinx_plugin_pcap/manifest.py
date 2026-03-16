"""PCAP plugin manifest — Suricata alerts, Zeek logs, tshark streams."""

MANIFEST = {
    "name": "sphinx-plugin-pcap",
    "version": "0.1.0",
    "description": "PCAP evidence: Suricata alerts, Zeek connection logs, tshark TCP streams",

    "ingest_handlers": {
        # Suricata EVE event types
        "suricata_alert": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_suricata",
        "suricata_http": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_suricata_http",
        "suricata_dns": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_suricata_dns",
        "suricata_tls": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_suricata_tls",
        "suricata_fileinfo": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_suricata_fileinfo",
        "suricata_flow": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_suricata_flow",
        "suricata_smtp": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_suricata_smtp",
        "suricata_ssh": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_suricata_ssh",
        # Zeek log types
        "zeek_conn": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_conn",
        "zeek_dns": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_dns",
        "zeek_http": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_http",
        "zeek_ssl": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_ssl",
        "zeek_files": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_files",
        "zeek_x509": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_x509",
        "zeek_notice": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_notice",
        "zeek_weird": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_weird",
        "zeek_dhcp": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_dhcp",
        "zeek_smtp": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_smtp",
        "zeek_ssh": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_ssh",
        "zeek_rdp": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_rdp",
        "zeek_pe": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_pe",
        "zeek_dpd": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_dpd",
        "zeek_ntp": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_ntp",
        "zeek_software": "sphinx.plugins.sphinx_plugin_pcap.ingest:ingest_zeek_software",
        # tshark TCP streams
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