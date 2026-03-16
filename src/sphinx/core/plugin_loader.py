"""Sphinx plugin loader — discovers, validates, and registers plugins."""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from sphinx.core.db import get_cursor

log = logging.getLogger(__name__)


@dataclass
class PluginRegistry:
    """Central registry of all loaded plugins and their handlers."""

    plugins: dict[str, dict] = field(default_factory=dict)
    ingest_handlers: dict[str, Callable] = field(default_factory=dict)
    ocsf_mappers: dict[str, Callable] = field(default_factory=dict)
    precompute_fns: list[Callable] = field(default_factory=list)
    prompts: dict[str, Any] = field(default_factory=dict)
    dashboard_widgets: list[Callable] = field(default_factory=list)


# Global registry
_registry = PluginRegistry()


def get_registry() -> PluginRegistry:
    return _registry


def _resolve(dotted_path: str) -> Any:
    """Import and return an object from a dotted path like 'pkg.mod:func'."""
    if ":" in dotted_path:
        module_path, attr_name = dotted_path.rsplit(":", 1)
    else:
        module_path, attr_name = dotted_path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, attr_name)


def _run_plugin_migrations(
    plugin_name: str, migrations: list[str], plugin_dir: str | None = None,
) -> None:
    """Run plugin SQL migrations that haven't been applied yet."""
    import pathlib

    with get_cursor() as cur:
        for migration_path in migrations:
            basename = migration_path.rsplit("/", 1)[-1]

            # Check if already applied
            cur.execute(
                """SELECT 1 FROM plugin_migrations
                   WHERE plugin_name = %s AND migration_file = %s""",
                (plugin_name, basename),
            )
            if cur.fetchone():
                continue

            # Read and execute the migration
            try:
                sql_file = None

                # Try plugin_dir hint first (bundled plugins)
                if plugin_dir:
                    candidate = pathlib.Path(plugin_dir) / migration_path
                    if candidate.exists():
                        sql_file = candidate

                # Try loading from installed package
                if not sql_file:
                    try:
                        module_base = plugin_name.replace("-", "_")
                        sql_module = importlib.import_module(module_base)
                        pkg_dir = pathlib.Path(sql_module.__file__).parent
                        candidate = pkg_dir / migration_path
                        if candidate.exists():
                            sql_file = candidate
                    except ImportError:
                        pass

                # Fall back to relative path
                if not sql_file:
                    sql_file = pathlib.Path(migration_path)

                sql = sql_file.read_text()
                cur.execute(sql)
                cur.execute(
                    """INSERT INTO plugin_migrations (plugin_name, migration_file)
                       VALUES (%s, %s)""",
                    (plugin_name, basename),
                )
                cur.connection.commit()
                log.info("Plugin %s: applied migration %s", plugin_name, basename)
            except Exception as e:
                log.warning("Plugin %s: migration %s failed: %s", plugin_name, basename, e)
                cur.connection.rollback()


def load_plugin(manifest: dict, plugin_dir: str | None = None) -> None:
    """Validate and register a single plugin from its manifest dict."""
    name = manifest.get("name", "unknown")
    version = manifest.get("version", "0.0.0")

    log.info("Loading plugin: %s v%s", name, version)

    # Register ingest handlers
    for record_type, handler_path in manifest.get("ingest_handlers", {}).items():
        try:
            handler = _resolve(handler_path)
            _registry.ingest_handlers[record_type] = handler
            log.info("  Registered ingest handler: %s", record_type)
        except Exception as e:
            log.warning("  Failed to load ingest handler %s: %s", record_type, e)

    # Register OCSF mappers
    for view_name, mapper_path in manifest.get("ocsf_mappers", {}).items():
        try:
            mapper = _resolve(mapper_path)
            _registry.ocsf_mappers[view_name] = mapper
            log.info("  Registered OCSF mapper: %s", view_name)
        except Exception as e:
            log.warning("  Failed to load OCSF mapper %s: %s", view_name, e)

    # Register precompute functions
    for fn_path in manifest.get("precompute", []):
        try:
            fn = _resolve(fn_path)
            _registry.precompute_fns.append(fn)
            log.info("  Registered precompute: %s", fn_path)
        except Exception as e:
            log.warning("  Failed to load precompute %s: %s", fn_path, e)

    # Register prompts
    for prompt_name, prompt_path in manifest.get("prompts", {}).items():
        try:
            prompt_obj = _resolve(prompt_path)
            _registry.prompts[prompt_name] = prompt_obj
            log.info("  Registered prompt: %s", prompt_name)
        except Exception as e:
            log.warning("  Failed to load prompt %s: %s", prompt_name, e)

    # Register dashboard widgets
    for widget_path in manifest.get("dashboard_widgets", []):
        try:
            widget = _resolve(widget_path)
            _registry.dashboard_widgets.append(widget)
            log.info("  Registered widget: %s", widget_path)
        except Exception as e:
            log.warning("  Failed to load widget %s: %s", widget_path, e)

    # Run migrations
    migrations = manifest.get("migrations", [])
    if migrations:
        _run_plugin_migrations(name, migrations, plugin_dir=plugin_dir)

    _registry.plugins[name] = {
        "version": version,
        "description": manifest.get("description", ""),
    }
    log.info("Plugin %s v%s loaded successfully", name, version)


def discover_plugins() -> None:
    """Scan for installed sphinx_plugin_* packages and load their manifests."""
    import pkgutil

    for importer, modname, ispkg in pkgutil.iter_modules():
        if not modname.startswith("sphinx_plugin_"):
            continue
        try:
            manifest_mod = importlib.import_module(f"{modname}.manifest")
            manifest = getattr(manifest_mod, "MANIFEST", None)
            if manifest:
                load_plugin(manifest)
            else:
                log.warning("Plugin %s has no MANIFEST dict", modname)
        except ImportError as e:
            log.debug("Could not load plugin %s: %s", modname, e)
        except Exception as e:
            log.warning("Error loading plugin %s: %s", modname, e)


def load_bundled_plugins() -> None:
    """Load plugins bundled in src/sphinx/plugins/."""
    import pathlib
    plugins_dir = pathlib.Path(__file__).parent.parent / "plugins"
    if not plugins_dir.exists():
        return

    for plugin_dir in sorted(plugins_dir.iterdir()):
        if not plugin_dir.is_dir() or plugin_dir.name.startswith("_"):
            continue
        manifest_file = plugin_dir / "manifest.py"
        if not manifest_file.exists():
            continue
        try:
            spec = importlib.util.spec_from_file_location(
                f"{plugin_dir.name}.manifest", manifest_file
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            manifest = getattr(mod, "MANIFEST", None)
            if manifest:
                load_plugin(manifest, plugin_dir=str(plugin_dir))
        except Exception as e:
            log.warning("Error loading bundled plugin %s: %s", plugin_dir.name, e)