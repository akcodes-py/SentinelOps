"""Environment-driven configuration (PDR 5, 8)."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    mode: str = Field(default="defended", pattern="^(baseline|defended)$")
    db_url: str = f"sqlite:///{(ROOT / 'data' / 'sentinel.db').as_posix()}"
    policy_path: str = str(ROOT / "policy.yaml")
    policy_schema_path: str = str(ROOT / "policy.schema.json")
    jwt_secret: str = "local-dev-secret-change-me-32bytes!"
    jwt_expiry_minutes: int = 15
    trusted_proxies: str = "127.0.0.1,::1"
    log_path: str = str(ROOT / "logs" / "sentinel.jsonl")
    vector_backend: str = "memory"  # memory | chroma
    pii_backend: str = "regex"      # regex | presidio
    llm_backend: str = "mock"       # mock | openai | hf
    temperature: float = 0.0
    corpus_path: str = str(ROOT / "data" / "corpus.json")
    results_dir: str = str(ROOT / "results")

    @property
    def is_defended(self) -> bool:
        return self.mode == "defended"

    @property
    def trusted_proxy_set(self) -> set[str]:
        return {p.strip() for p in self.trusted_proxies.split(",") if p.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
    os.environ.pop("SENTINEL_MODE", None)
