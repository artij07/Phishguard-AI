from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    app_name: str = "PhishGuard AI"
    app_version: str = "1.0.0"
    database_url: str = f"sqlite:///{BASE_DIR / 'phishguard.db'}"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    ai_provider: str = "disabled"
    ai_api_key: str | None = None
    ai_model: str = "gpt-4o-mini"

    class Config:
        env_file = BASE_DIR / ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()
