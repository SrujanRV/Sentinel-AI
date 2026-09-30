"""Application configuration loaded from environment variables.

All settings are read via pydantic-settings so the actual values live in
.env (git-ignored) and the schema lives here.  Tests override individual
settings by patching os.environ before importing the settings object.
"""

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

    # --- API auth ---
    sentinel_api_key: str = Field(
        ..., description="Bearer token clients must supply."
    )

    # --- App behaviour ---
    app_env: str = Field("development", description="development | production")
    log_level: str = Field("INFO", description="Python logging level.")


# Module-level singleton; import this object everywhere.
settings = Settings()  # type: ignore[call-arg]
