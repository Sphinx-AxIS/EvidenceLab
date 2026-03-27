"""Windows Event Log plugin manifest."""

MANIFEST = {
    "name": "sphinx-plugin-winevt",
    "version": "0.1.0",
    "description": "Windows Event Logs: Security, PowerShell, Sysmon, Task Scheduler, Application, System",

    "ingest_handlers": {
        "win_evt_security": "sphinx.plugins.sphinx_plugin_winevt.ingest:ingest_security",
        "win_evt_powershell": "sphinx.plugins.sphinx_plugin_winevt.ingest:ingest_powershell",
        "win_evt_sysmon": "sphinx.plugins.sphinx_plugin_winevt.ingest:ingest_sysmon",
        "win_evt_taskscheduler": "sphinx.plugins.sphinx_plugin_winevt.ingest:ingest_taskscheduler",
        "win_evt_application": "sphinx.plugins.sphinx_plugin_winevt.ingest:ingest_application",
        "win_evt_system": "sphinx.plugins.sphinx_plugin_winevt.ingest:ingest_system",
    },

    "ocsf_mappers": {
        "auth_events": "sphinx.plugins.sphinx_plugin_winevt.ocsf:map_auth_events",
    },

    "prompts": {
        "winevt_system": "sphinx.plugins.sphinx_plugin_winevt.prompts:SYSTEM_PROMPT",
        "winevt_docs": "sphinx.plugins.sphinx_plugin_winevt.prompts:DOC_SECTIONS",
    },

    "precompute": [
        "sphinx.plugins.sphinx_plugin_winevt.precompute:logon_summary",
        "sphinx.plugins.sphinx_plugin_winevt.precompute:event_id_counts",
        "sphinx.plugins.sphinx_plugin_winevt.precompute:powershell_commands",
        "sphinx.plugins.sphinx_plugin_winevt.precompute:process_creation_summary",
    ],

    "migrations": [
        "sql/001_winevt_views.sql",
    ],

    "dashboard_widgets": [],
}
