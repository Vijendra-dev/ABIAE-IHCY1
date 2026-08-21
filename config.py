"""
Configuration settings for the Brand Intelligence Backend.
Loads environment variables with robust defaults and validation.
"""

import json
import os
from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Service meta
    APP_NAME: str = "Brand Intelligence Backend"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./data/brand_intel.db",
        description="Async database connection string (PostgreSQL asyncpg or SQLite aiosqlite)",
    )

    # TrustLens-AI Service Configuration
    TRUSTLENS_BASE_URL: str = Field(
        default="http://localhost:8001",
        description="Base URL of the TrustLens-AI service",
    )
    TRUSTLENS_TIMEOUT_SECONDS: float = Field(
        default=30.0,
        description="HTTP client timeout for TrustLens-AI analysis calls",
    )

    # Antigravity Platform Integration
    ANTIGRAVITY_BASE_URL: str = Field(
        default="https://antigravity.example.com",
        description="Base URL of the external Antigravity risk platform",
    )
    ANTIGRAVITY_API_KEY: str = Field(
        default="ag_sec_key_demo123456789",
        description="API Key / Bearer token for Antigravity ingestion API",
    )
    RISK_THRESHOLD_FOR_ANTIGRAVITY: int = Field(
        default=70,
        ge=0,
        le=100,
        description="Minimum combined risk score required to dispatch event to Antigravity",
    )

    # openSquat Brand Monitoring List
    BRAND_LIST: Union[List[str], str] = Field(
        default=["google", "microsoft", "paypal", "apple", "netflix"],
        description="List of target brand names to protect against domain squatting",
    )

    # Scheduler & Execution Settings
    OPENSQUAT_CRON_SCHEDULE: str = Field(
        default="0 0 * * *",
        description="Cron expression for daily openSquat monitoring",
    )
    AUTO_TRIGGER_ANALYSIS: bool = Field(
        default=True,
        description="Whether to automatically run TrustLens analysis for discovered squatted domains",
    )

    # Storage
    DATA_DIR: str = Field(
        default="./data",
        description="Path to directory for scan outputs and cached feeds",
    )

    @field_validator("BRAND_LIST", mode="before")
    @classmethod
    def parse_brand_list(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, list):
            return [str(b).strip().lower() for b in v if str(b).strip()]
        if isinstance(v, str):
            v_trimmed = v.strip()
            if v_trimmed.startswith("[") and v_trimmed.endswith("]"):
                try:
                    parsed = json.loads(v_trimmed)
                    if isinstance(parsed, list):
                        return [str(b).strip().lower() for b in parsed if str(b).strip()]
                except Exception:
                    pass
            # Comma-separated fallback
            return [b.strip().lower() for b in v.split(",") if b.strip()]
        return ["google", "microsoft", "paypal", "apple", "netflix"]


settings = Settings()

# Ensure data directory exists
os.makedirs(settings.DATA_DIR, exist_ok=True)
