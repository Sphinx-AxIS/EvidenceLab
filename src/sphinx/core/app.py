"""Sphinx API — FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from sphinx.core.config import load_settings
from sphinx.core.db import close_pool, init_pool

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown: initialize DB pool, seed admin if needed."""
    settings = app.state.settings
    init_pool(settings)
    _ensure_admin(settings)
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

    app.include_router(auth_router)
    app.include_router(case_router)

    @app.get("/")
    async def root():
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/health")
    async def health():
        return JSONResponse({"healthy": True})

    return app