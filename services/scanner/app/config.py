from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PORT: int = 8001
    SCANNER_API_SECRET: str
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    URLHAUS_ENABLED: bool = True
    LLM_API_KEY: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
