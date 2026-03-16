"""Sphinx API — FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from sphinx.core.config import load_settings
from sphinx.core.db import close_pool, init_pool

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown: initialize DB pool, seed admin if needed."""
    settings = app.state.settings
    init_pool(settings)
    _ensure_admin(settings)

    from sphinx.core.plugin_loader import load_bundled_plugins
    load_bundled_plugins()

    log.info("Sphinx API started")
    yield
    close_pool()
    log.info("Sphinx API stopped")


def _ensure_admin(settings):
    """Create a default admin user if the users table is empty."""
    from sphinx.core.auth import hash_password
    from sphinx.core.db import get_cursor

    with get_cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM users")
        if cur.fetchone()["n"] == 0:
            import uuid
            pw_hash = hash_password("admin1234")
            cur.execute(
                """INSERT INTO users (id, username, password_hash, role)
                   VALUES (%s, 'admin', %s, 'admin')""",
                (str(uuid.uuid4()), pw_hash),
            )
            cur.connection.commit()
            log.info("Created default admin user (username: admin, password: admin1234)")


def create_app() -> FastAPI:
    settings = load_settings()

    app = FastAPI(
        title="Sphinx AI IR Assistant",
        version="0.1.0",
        description="Plugin-based incident response investigation platform",
        lifespan=lifespan,
    )
    app.state.settings = settings

    # ── Routes ─────────────────────────────────────
    from sphinx.core.auth_routes import router as auth_router
    from sphinx.core.case_manager import router as case_router
    from sphinx.core.dashboard import router as dashboard_router
    from sphinx.core.task_runner import router as task_router
    from sphinx.core.ingest_routes import router as ingest_router
    from sphinx.core.analytics_routes import router as analytics_router

    app.include_router(auth_router)
    app.include_router(case_router)
    app.include_router(dashboard_router)
    app.include_router(task_router)
    app.include_router(ingest_router)
    app.include_router(analytics_router)

    # ── SSE streaming ─────────────────────────────
    from sphinx.core.sse import router as sse_router
    app.include_router(sse_router)

    # ── Frontend (server-rendered UI) ─────────────
    from sphinx.core.frontend import router as ui_router
    app.include_router(ui_router)
    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

    # ── Report endpoint ────────────────────────────
    from sphinx.core.auth import CurrentUser, check_case_access
    from fastapi import Depends, Request

    @app.get("/cases/{case_id}/report")
    async def get_report(
        case_id: str,
        request: Request,
        user=Depends(CurrentUser(required_role="analyst")),
    ):
        check_case_access(user, case_id)
        from sphinx.core.report import generate_report
        return generate_report(request.app.state.settings, case_id)

    # ── Query learning endpoint (admin) ────────────
    @app.post("/admin/query-learning")
    async def run_query_learning(
        user=Depends(CurrentUser(required_role="admin")),
    ):
        from sphinx.core.query_learner import mine_worklog
        return mine_worklog()

    @app.get("/")
    async def root():
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/health")
    async def health():
        return JSONResponse({"healthy": True})

    return app