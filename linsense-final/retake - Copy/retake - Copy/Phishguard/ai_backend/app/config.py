"""Application configuration loaded from environment variables.

All sensitive values (API keys, access tokens) are read server-side only and
never exposed to the Chrome extension frontend.
"""

import json
from functools import lru_cache
from typing import Annotated, Any, List

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Backend configuration."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8787
    log_level: str = "INFO"

    # Reputation provider API keys (server-side only)
    urlscan_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    pulsedive_api_key: str = ""
    metadefender_api_key: str = ""
    virustotal_api_key: str = ""

    # Optional LLM for AI explanations
    llm_provider: str = "none"
    llm_api_key: str = ""
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"

    # CORS origins allowed to call the backend directly from a web page.
    cors_origins: Annotated[List[str], NoDecode] = ["http://127.0.0.1", "https://127.0.0.1"]

    # API access token for authenticated calls (required in production / HTTPS)
    api_access_token: str = ""

    # Model artifacts
    model_path: str = "ml/model.joblib"
    model_meta_path: str = "ml/model_meta.json"

    # Timeouts (seconds)
    provider_timeout: float = 10.0
    reputation_timeout: float = 50.0

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> List[str]:
        if v is None or v == "":
            return ["http://127.0.0.1", "https://127.0.0.1"]
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return ["http://127.0.0.1", "https://127.0.0.1"]
            if s.startswith("["):
                parsed = json.loads(s)
                return parsed if isinstance(parsed, list) else [str(parsed)]
            return [part.strip() for part in s.split(",") if part.strip()]
        if isinstance(v, (list, tuple)):
            return list(v)
        return [str(v)]


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
