import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, AliasChoices

# Explicitly locate repository root .env
POSSIBLE_ROOT_ENV_PATHS = [
    Path(__file__).resolve().parents[4] / ".env",   # From app/config/settings.py to repo root
    Path(__file__).resolve().parents[3] / ".env",   # From app/settings.py to repo root
    Path.cwd() / ".env",                            # If run from root
    Path.cwd().parent / ".env",                     # If run from services
    Path.cwd().parents[1] / ".env",                 # If run from services/scanner
]

ROOT_ENV_PATH = next((p for p in POSSIBLE_ROOT_ENV_PATHS if p.is_file()), Path(".env"))


class Settings(BaseSettings):
    PORT: int = Field(default=8001, validation_alias=AliasChoices("PORT", "SCANNER_PORT"))
    SCANNER_API_SECRET: str
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    URLHAUS_ENABLED: bool = True
    LLM_API_KEY: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=str(ROOT_ENV_PATH),
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
