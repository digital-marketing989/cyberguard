"""
CyberGuard Configuration
Reads settings from environment variables / .env file
"""
from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import List
import os


class Settings(BaseSettings):
    # App
    APP_NAME: str = "CyberGuard"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Database
    DATABASE_URL: str = "sqlite:///./cyberguard.db"

    # Security
    SECRET_KEY: str = "dev-secret-key-change-in-production"

    # OpenRouter LLM
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    LLM_MODEL: str = "openai/gpt-4o-mini"
    LLM_TIMEOUT: int = 30

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

    # File uploads
    MAX_UPLOAD_SIZE_MB: int = 50
    ALLOWED_IMAGE_TYPES: List[str] = ["image/jpeg", "image/png", "image/webp", "image/gif"]
    ALLOWED_AUDIO_TYPES: List[str] = ["audio/wav", "audio/mpeg", "audio/ogg", "audio/flac"]
    ALLOWED_VIDEO_TYPES: List[str] = ["video/mp4", "video/avi", "video/mov", "video/webm"]
    ALLOWED_CSV_TYPES: List[str] = ["text/csv", "application/csv", "text/plain"]

    # Risk thresholds
    RISK_SAFE_MAX: int = 15
    RISK_LOW_MAX: int = 35
    RISK_MEDIUM_MAX: int = 60
    RISK_HIGH_MAX: int = 80
    # > 80 = Critical

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
