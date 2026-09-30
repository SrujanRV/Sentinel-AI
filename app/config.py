"""Application configuration loaded from environment variables.

All settings are read via pydantic-settings. Actual values live in
.env (git-ignored); the schema lives here. The lru_cache'd get_settings()
function is the single source of truth - inject it via FastAPI Depends()
so tests can override it cleanly without touching real secrets.
"""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central config - every secret comes from the environment, never code."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # --- OpenAI ---
    openai_api_key: str = Field(..., description="OpenAI API key (required).")
    openai_model: str = Field(
        "gpt-4o-mini", description="Chat completion model name."
    )
    embedding_model: str = Field(
        "text-embedding-3-small", description="Text embedding model name."
    )

    # --- API auth (comma-separated list of accepted keys) ---
    sentinel_api_keys: str = Field(
        ...,
        description="Comma-separated valid API keys for X-API-Key header auth.",
    )

    # --- App behaviour ---
    app_env: str = Field("development", description="development | production")
    log_level: str = Field("INFO", description="Python logging level.")

    @property
    def api_key_set(self) -> frozenset[str]:
        """Parse the comma-separated key list into an immutable set."""
        return frozenset(
            k.strip() for k in self.sentinel_api_keys.split(",") if k.strip()
        )


@lru_cache
def get_settings() -> Settings:
    """Return the cached Settings singleton.

    Using lru_cache means the Settings object is built once from the
    environment.  Tests clear this cache via get_settings.cache_clear()
    before patching os.environ to guarantee a fresh read.
    """
    return Settings()  # type: ignore[call-arg]
