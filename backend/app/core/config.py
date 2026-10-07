import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "ScamShield"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite:///./scamshield.db"

    # Authentication & Security
    AUTH_ENABLED: bool = False
    SECRET_KEY: str = "scamshield-default-development-secret-key-change-in-prod"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    CORS_ORIGINS: List[str] = ["*"]
    RATE_LIMIT_PER_MINUTE: int = 60
    MAX_UPLOAD_SIZE_MB: int = 10

    # Detection Thresholds
    RISK_THRESHOLD_SAFE: int = 29
    RISK_THRESHOLD_SUSPICIOUS: int = 69
    RISK_THRESHOLD_SCAM: int = 70

    # AI & Intelligence Providers
    LLM_PROVIDER: str = "mock"  # mock, gemini, openai, local
    LLM_API_KEY: Optional[str] = None
    LLM_MODEL: str = "gemini-1.5-flash"

    VIRUSTOTAL_API_KEY: Optional[str] = None
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    WHOIS_API_KEY: Optional[str] = None

    OCR_PROVIDER: str = "tesseract"  # tesseract, easyocr, paddleocr, mock
    OCR_API_KEY: Optional[str] = None

    STT_PROVIDER: str = "mock"  # whisper, mock
    STT_API_KEY: Optional[str] = None

    # Temp file storage
    TEMP_STORAGE_DIR: str = "./tmp_uploads"

    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()
