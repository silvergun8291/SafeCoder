from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import field_validator, ValidationInfo
from pydantic_settings import BaseSettings

# ⬅️ 2. config.py 파일의 위치를 기준으로 backend 폴더 경로를 잡습니다.
#    config.py -> app/core/ -> app/ -> backend/
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# ⬅️ 3. .env 파일의 절대 경로를 지정합니다.
ENV_FILE_PATH = BASE_DIR / ".env"

# --- RAG 설정 상수 ---
# Code RAG에서 사용된 모델 정보
CODE_RAG_COLLECTION_NAME_DEFAULT: str = "secure_coding_knowledge_qdrant"
CODE_RAG_EMBEDDING_MODEL_DEFAULT: str = "sentence-transformers/multi-qa-distilbert-cos-v1"
CODE_RAG_VECTOR_DIMENSION: int = 768

# Text RAG에서 사용할 모델 및 컬렉션 정보
TEXT_RAG_COLLECTION_NAME_DEFAULT: str = "text_db"
RULE_RAG_COLLECTION_NAME_DEFAULT: str = "rule_db"
TEXT_RAG_EMBEDDING_MODEL_DEFAULT: str = "solar-embedding-1-large"
# Solar 임베딩 모델의 차원은 768입니다. (CodeBERT와 동일)
TEXT_RAG_VECTOR_DIMENSION: int = 768

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
    DB_PASSWORD: str = "postgres"
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "safecoder"

    # 4. SQLAlchemy URL (동기/비동기)
    SQLALCHEMY_DATABASE_URL: Optional[str] = None
    ASYNC_SQLALCHEMY_DATABASE_URL: Optional[str] = None

    # 5. Qdrant (Phase 3)
    # ⬇️ QDRANT_URL은 기존에 있었으나, 이제 RAG의 핵심 설정으로 사용됩니다.
    QDRANT_URL: str = "http://localhost:6333"

    # 5. Code RAG 설정 (CodeBERT 기반)
    # ⬇️ Code RAG 관련 설정이 새로 추가되었습니다.
    CODE_COLLECTION_NAME: str = CODE_RAG_COLLECTION_NAME_DEFAULT
    CODE_EMBEDDING_MODEL: str = CODE_RAG_EMBEDDING_MODEL_DEFAULT
    CODE_VECTOR_DIMENSION: int = CODE_RAG_VECTOR_DIMENSION

    # 6. Text RAG 설정 (Solar 기반)
    # ⬇️ Text RAG 관련 설정이 새로 추가되었습니다.
    TEXT_COLLECTION_NAME: str = TEXT_RAG_COLLECTION_NAME_DEFAULT
    RULE_COLLECTION_NAME: str = RULE_RAG_COLLECTION_NAME_DEFAULT
    TEXT_EMBEDDING_MODEL: str = TEXT_RAG_EMBEDDING_MODEL_DEFAULT
    TEXT_VECTOR_DIMENSION: int = TEXT_RAG_VECTOR_DIMENSION

    # 7. 스캐너 및 LLM 설정 (기존에 있던 내용)
    SCANNER_TIMEOUT_SECONDS: int = 180
    LLM_MAX_RETRIES: int = 3

    # 8. LLM 캐시 설정
    # 최대 캐시 항목 수, TTL(초). TTL=0이면 만료 사용 안 함.
    LLM_CACHE_MAX: int = 128
    LLM_CACHE_TTL_SECONDS: int = 0

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