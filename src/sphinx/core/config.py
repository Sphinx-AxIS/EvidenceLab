"""Sphinx configuration — loads settings from environment variables."""

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    # Database
    database_url: str = ""
    db_pool_min: int = 2
    db_pool_max: int = 10

    # JWT
    jwt_secret: str = "changeme"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480

    # LLM
    lm_studio_url: str = "http://localhost:1234/v1"
    llm_model: str = "qwen2.5-coder-32b-instruct"
    rlm_max_steps: int = 15
    rlm_max_step_seconds: int = 120

    # REPL
    repl_image: str = "sphinx-repl:latest"
    repl_timeout: int = 120


def load_settings() -> Settings:
    """Build Settings from environment variables."""
    return Settings(
        database_url=os.environ.get(
            "DATABASE_URL",
            "postgresql://sphinx:changeme@localhost:5432/sphinx",
        ),
        db_pool_min=int(os.environ.get("SPHINX_POOL_MIN", "2")),
        db_pool_max=int(os.environ.get("SPHINX_POOL_MAX", "10")),
        jwt_secret=os.environ.get("JWT_SECRET", "changeme"),
        jwt_algorithm=os.environ.get("JWT_ALGORITHM", "HS256"),
        jwt_expire_minutes=int(os.environ.get("JWT_EXPIRE_MINUTES", "480")),
        lm_studio_url=os.environ.get("LM_STUDIO_URL", "http://localhost:1234/v1"),
        llm_model=os.environ.get("LLM_MODEL", "qwen2.5-coder-32b-instruct"),
        rlm_max_steps=int(os.environ.get("RLM_MAX_STEPS", "15")),
        rlm_max_step_seconds=int(os.environ.get("RLM_MAX_STEP_SECONDS", "120")),
        repl_image=os.environ.get("REPL_IMAGE", "sphinx-repl:latest"),
        repl_timeout=int(os.environ.get("REPL_TIMEOUT", "120")),
    )