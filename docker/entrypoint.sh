#!/usr/bin/env bash
set -euo pipefail

# -------------------------------------------------------------------
# Sphinx entrypoint — dispatches to API server or REPL standby
# -------------------------------------------------------------------

wait_for_db() {
    local retries=30
    echo "[sphinx] Waiting for PostgreSQL..."
    while ! pg_isready -h db -U sphinx -q 2>/dev/null; do
        retries=$((retries - 1))
        if [ "$retries" -le 0 ]; then
            echo "[sphinx] ERROR: PostgreSQL not ready after 60s" >&2
            exit 1
        fi
        sleep 2
    done
    echo "[sphinx] PostgreSQL is ready."
}

run_bootstrap() {
    if [ "${SPHINX_RUN_BOOTSTRAP:-0}" = "1" ] && [ -f ./bootstrap_postgres.sh ]; then
        echo "[sphinx] Running database bootstrap..."
        bash ./bootstrap_postgres.sh
    fi
}

export PYTHONPATH="/app/src:${PYTHONPATH:-}"

case "${1:-}" in
    --api)
        wait_for_db
        run_bootstrap
        echo "[sphinx] Starting API server on :8000"
        exec python -m uvicorn sphinx.core.app:create_app \
            --factory --host 0.0.0.0 --port 8000 \
            --reload --reload-dir /app/src
        ;;
    --repl)
        wait_for_db
        REPL_SOCK="${REPL_SOCKET:-/tmp/repl/sphinx_repl.sock}"
        echo "[sphinx] Starting REPL server on ${REPL_SOCK}"
        exec python -m sphinx.core.repl_server \
            --socket "${REPL_SOCK}" \
            --db-url "${DATABASE_URL:-postgresql://sphinx:changeme@db:5432/sphinx}"
        ;;
    *)
        echo "Usage: entrypoint.sh [--api | --repl]"
        exit 1
        ;;
esac