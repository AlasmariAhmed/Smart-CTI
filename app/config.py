"""Application settings — loads .env + config.yaml into one typed object."""
from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config.yaml"
DATA_DIR = PROJECT_ROOT / "data"

log = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Environment-driven settings. Anything secret lives here."""

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Secrets / per-environment ---
    otx_api_key: str = Field(default="", alias="OTX_API_KEY")

    # --- DB / server ---
    database_url: str = Field(default=f"sqlite:///{PROJECT_ROOT / 'cti.db'}", alias="DATABASE_URL")
    host: str = Field(default="127.0.0.1", alias="HOST")
    port: int = Field(default=8000, alias="PORT")

    # --- Scoring / enrichment ---
    relevance_score_threshold: int = Field(default=40, alias="RELEVANCE_SCORE_THRESHOLD")
    geoip_db_path: str = Field(default=str(DATA_DIR / "GeoLite2-Country.mmdb"), alias="GEOIP_DB_PATH")

    # --- Logging ---
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")


def _load_yaml() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        log.warning("config.yaml not found at %s — using defaults", CONFIG_PATH)
        return {}
    with CONFIG_PATH.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


@lru_cache(maxsize=1)
def get_yaml_config() -> dict[str, Any]:
    return _load_yaml()


def setup_logging() -> None:
    """Idempotent logging setup. Safe to call multiple times."""
    level = get_settings().log_level.upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
