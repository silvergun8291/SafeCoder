# app/main.py

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.exceptions import HTTPException
from starlette.middleware.cors import CORSMiddleware

# --- 1. 모듈 임포트 ---
from app.api.routers import api_router
from app.core.exceptions import (
    AppException,
    app_exception_handler,
    http_exception_handler,
    generic_exception_handler
)
from app.core.logging_config import setup_logging
from app.db.database import Base, sync_engine, async_engine

# ⭐ Piranha Rule 모델 import 추가
from app.models.models import PiranhaRule


# --- 2. 애플리케이션 수명 주기 (LifeSpan) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """애플리케이션 시작/종료 시 실행할 작업"""

    # === 시작 시 ===
    setup_logging()
    logger = logging.getLogger("app")
    logger.info("--- 애플리케이션 시작 ---")

    # 데이터베이스 테이블 생성
    logger.info("데이터베이스 테이블 생성 (존재하지 않는 경우)...")
    try:
        with sync_engine.begin() as conn:
            Base.metadata.create_all(conn)
        logger.info("✅ 테이블 생성 완료 (piranha_rules)")
    except Exception as e:
        logger.error(f"❌ DB 연결 실패: {e}", exc_info=True)
        raise

    yield

    # === 종료 시 ===
    logger.info("--- 애플리케이션 종료 ---")
    try:
        await async_engine.dispose()
        sync_engine.dispose()
        logger.info("✅ DB 연결 풀 정리 완료")
    except Exception as e:
        logger.error(f"❌ 리소스 정리 실패: {e}")


# --- 3. FastAPI 앱 생성 ---
app = FastAPI(
    title="시큐어 코딩 챗봇 API",
    description="Piranha Rule 기반 자동 취약점 패치",
    version="0.3.0 (Piranha Rule)",
    lifespan=lifespan
)

# --- 4. CORS 미들웨어 ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 5. 예외 핸들러 ---
app.add_exception_handler(AppException, app_exception_handler)
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# --- 6. API 라우터 ---
app.include_router(api_router, prefix="/api")


# --- 7. 루트 엔드포인트 ---
@app.get("/", include_in_schema=False)
async def root():
    return {"message": "Piranha Rule API - /docs 로 이동하세요."}
