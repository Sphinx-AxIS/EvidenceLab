"""Sphinx database — PostgreSQL connection pool using psycopg 3."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Generator

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from sphinx.core.config import Settings

log = logging.getLogger(__name__)

_pool: ConnectionPool | None = None


def init_pool(settings: Settings) -> ConnectionPool:
    """Create the global connection pool. Call once at startup."""
    global _pool
    if _pool is not None:
        return _pool
    _pool = ConnectionPool(
        conninfo=settings.database_url,
        min_size=settings.db_pool_min,
        max_size=settings.db_pool_max,
        kwargs={"row_factory": dict_row},
    )
    log.info("Database pool initialized (%d–%d connections)",
             settings.db_pool_min, settings.db_pool_max)
    return _pool


def get_pool() -> ConnectionPool:
    """Return the global pool. Raises if not initialized."""
    if _pool is None:
        raise RuntimeError("Database pool not initialized — call init_pool() first")
    return _pool


@contextmanager
def get_conn() -> Generator[psycopg.Connection, None, None]:
    """Borrow a connection from the pool."""
    pool = get_pool()
    with pool.connection() as conn:
        yield conn


@contextmanager
def get_cursor() -> Generator[psycopg.Cursor, None, None]:
    """Borrow a connection and return a dict-row cursor."""
    with get_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            yield cur


def close_pool() -> None:
    """Shut down the pool. Call at application shutdown."""
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None
        log.info("Database pool closed")