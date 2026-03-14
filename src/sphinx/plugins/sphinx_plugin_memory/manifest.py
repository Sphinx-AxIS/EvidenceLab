"""Memory forensics plugin manifest — Volatility 3 output."""

MANIFEST = {
    "name": "sphinx-plugin-memory",
    "version": "0.1.0",
    "description": "Memory forensics: Volatility 3 process, network, registry, and DLL output",

    "ingest_handlers": {
        "vol_pslist": "sphinx.plugins.sphinx_plugin_memory.ingest:ingest_pslist",
        "vol_netscan": "sphinx.plugins.sphinx_plugin_memory.ingest:ingest_netscan",
        "vol_cmdline": "sphinx.plugins.sphinx_plugin_memory.ingest:ingest_cmdline",
        "vol_dlllist": "sphinx.plugins.sphinx_plugin_memory.ingest:ingest_dlllist",
        "vol_handles": "sphinx.plugins.sphinx_plugin_memory.ingest:ingest_handles",
        "vol_malfind": "sphinx.plugins.sphinx_plugin_memory.ingest:ingest_malfind",
    },

    "ocsf_mappers": {},

    "prompts": {
        "memory_system": "sphinx.plugins.sphinx_plugin_memory.prompts:SYSTEM_PROMPT",
        "memory_docs": "sphinx.plugins.sphinx_plugin_memory.prompts:DOC_SECTIONS",
    },

    "precompute": [
        "sphinx.plugins.sphinx_plugin_memory.precompute:process_tree",
        "sphinx.plugins.sphinx_plugin_memory.precompute:network_connections",
        "sphinx.plugins.sphinx_plugin_memory.precompute:suspicious_processes",
    ],

    "migrations": [],
    "dashboard_widgets": [],
}