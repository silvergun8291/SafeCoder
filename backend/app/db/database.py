from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.core.config import get_settings
from typing import AsyncGenerator

settings = get_settings()

# --- 비동기 엔진 (FastAPI 구동용) ---
async_engine = create_async_engine(
    settings.ASYNC_SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
    echo=False,  # (개발 시 True로 설정하면 쿼리 로그 확인 가능)
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)

# --- 동기 엔진 (DB 마이그레이션 및 초기화용) ---
# Alembic 또는 main.py의 create_all은 동기 방식으로 실행되어야 함
sync_engine = create_engine(
    settings.SQLALCHEMY_DATABASE_URL,
)


# --- ORM 모델 기본 클래스 (SQLAlchemy 2.0) ---
class Base(DeclarativeBase):
    pass


# --- FastAPI 의존성 (Dependency) ---
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI 의존성 주입용 비동기 데이터베이스 세션 생성기
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise