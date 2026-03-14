"""Sphinx API — FastAPI application factory."""

from fastapi import FastAPI
from fastapi.responses import JSONResponse


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sphinx AI IR Assistant",
        version="0.1.0",
        description="Plugin-based incident response investigation platform",
    )

    @app.get("/")
    async def root():
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/health")
    async def health():
        return JSONResponse({"healthy": True})

    return app