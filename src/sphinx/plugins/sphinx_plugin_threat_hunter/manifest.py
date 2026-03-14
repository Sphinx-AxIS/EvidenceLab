"""Threat Hunter plugin manifest — cross-source correlation and MITRE mapping."""

MANIFEST = {
    "name": "sphinx-plugin-threat-hunter",
    "version": "0.2.0",
    "description": "Cross-source correlation, MITRE ATT&CK mapping, IOC aggregation",

    "ingest_handlers": {},

    "ocsf_mappers": {},

    "prompts": {
        "threat_hunter_system": "sphinx.plugins.sphinx_plugin_threat_hunter.prompts:SYSTEM_PROMPT",
    },

    "precompute": [
        "sphinx.plugins.sphinx_plugin_threat_hunter.precompute:ioc_summary",
        "sphinx.plugins.sphinx_plugin_threat_hunter.precompute:cross_source_ips",
        "sphinx.plugins.sphinx_plugin_threat_hunter.precompute:attack_surface",
    ],

    "migrations": [],
    "dashboard_widgets": [],
}