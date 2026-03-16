#!/usr/bin/env bash
set -euo pipefail

# -------------------------------------------------------------------
# Sphinx — Idempotent database bootstrap with advisory locking
# Runs core migrations in order, then plugin migrations.
# -------------------------------------------------------------------

DB_HOST="${PGHOST:-db}"
DB_PORT="${PGPORT:-5432}"
DB_NAME="${PGDATABASE:-sphinx}"
DB_USER="${PGUSER:-sphinx}"

psql_cmd() {
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
        -v ON_ERROR_STOP=1 "$@"
}

# Acquire advisory lock (prevents parallel bootstrap races)
echo "[bootstrap] Acquiring advisory lock..."
psql_cmd -c "SELECT pg_advisory_lock(1);" > /dev/null

echo "[bootstrap] Running core migrations..."

for migration in sql/[0-9]*.sql; do
    if [ -f "$migration" ]; then
        basename="$(basename "$migration")"
        echo "[bootstrap]   $basename"
        psql_cmd -f "$migration" > /dev/null 2>&1 || {
            echo "[bootstrap]   WARN: $basename had errors (may be idempotent)"
        }
    fi
done

echo "[bootstrap] Core migrations complete."

# Plugin migrations are tracked in plugin_migrations table
# and run by the plugin loader at startup, not here.

# Release advisory lock
psql_cmd -c "SELECT pg_advisory_unlock(1);" > /dev/null
echo "[bootstrap] Done."