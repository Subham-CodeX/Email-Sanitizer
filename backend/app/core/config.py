from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "PhishingTrack API"
    app_env: str = "development"
    api_prefix: str = "/api/v1"
    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_db: str = "phishingtrack"
    frontend_url: str = "http://localhost:5173"
    cors_origins: str = "http://localhost:5173"
    max_email_size_mb: int = 15
    max_attachment_metadata_items: int = 25
    max_url_items: int = 100

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]

    @property
    def max_email_size_bytes(self) -> int:
        return self.max_email_size_mb * 1024 * 1024

@lru_cache
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
