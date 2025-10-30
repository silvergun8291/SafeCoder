import os
from pydantic_settings import BaseSettings
from pydantic import field_validator, ValidationInfo
from functools import lru_cache
from typing import Optional
from pathlib import Path

# ⬅️ 2. config.py 파일의 위치를 기준으로 backend 폴더 경로를 잡습니다.
#    config.py -> app/core/ -> app/ -> backend/
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# ⬅️ 3. .env 파일의 절대 경로를 지정합니다.
ENV_FILE_PATH = BASE_DIR / ".env"


class Settings(BaseSettings):
    """
    애플리케이션 환경 변수 관리 (pydantic-settings 활용)
    .env 파일 > 환경 변수 순으로 로드
    """

    # 1. 환경
    APP_ENV: str = "development"

    # 2. API 키
    UPSTAGE_API_KEY: str

    # 3. 데이터베이스 설정
    DB_USER: str = "postgres"
    DB_PASSWORD: str
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "postgres"

    # 4. SQLAlchemy URL (동기/비동기)
    SQLALCHEMY_DATABASE_URL: Optional[str] = None
    ASYNC_SQLALCHEMY_DATABASE_URL: Optional[str] = None

    @field_validator("SQLALCHEMY_DATABASE_URL", mode='before')
    @classmethod
    def assemble_db_connection(cls, v: Optional[str], info: ValidationInfo) -> str:
        """동기 DB URL 생성 (e.g., 'postgresql://user:pass@host/db')"""
        if isinstance(v, str):
            return v
        values = info.data
        return (
            f"postgresql://{values.get('DB_USER')}:{values.get('DB_PASSWORD')}@"
            f"{values.get('DB_HOST')}:{values.get('DB_PORT')}/{values.get('DB_NAME')}"
        )

    @field_validator("ASYNC_SQLALCHEMY_DATABASE_URL", mode='before')
    @classmethod
    def assemble_async_db_connection(cls, v: Optional[str], info: ValidationInfo) -> str:
        """비동기 DB URL 생성 (e.g., 'postgresql+asyncpg://user:pass@host/db')"""
        if isinstance(v, str):
            return v
        values = info.data
        return (
            f"postgresql+asyncpg://{values.get('DB_USER')}:{values.get('DB_PASSWORD')}@"
            f"{values.get('DB_HOST')}:{values.get('DB_PORT')}/{values.get('DB_NAME')}"
        )

    # 5. Qdrant (Phase 3)
    QDRANT_URL: str = "http://localhost:6333"

    # 6. 스캐너 및 LLM 설정
    SCANNER_TIMEOUT_SECONDS: int = 180
    LLM_MAX_RETRIES: int = 3

    class Config:
        env_file = ENV_FILE_PATH
        env_file_encoding = "utf-8"
        extra = "ignore"


@lru_cache()
def get_settings():
    """설정 객체 의존성 주입용"""
    return Settings()