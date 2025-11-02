import logging
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.db.database import get_db

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get(
    "/shallow",
    summary="서버 Liveness 확인",
    response_description="서버가 구동 중인 경우 'ok' 반환",
)
async def health_check_shallow():
    """
    (Liveness Probe)
    컨테이너가 실행 중인지 확인하기 위한 최소한의 헬스 체크
    """
    return {"status": "ok"}


@router.get(
    "/deep",
    summary="서버 Readiness 확인 (DB 포함)",
    response_description="서버와 데이터베이스 연결이 모두 정상이면 'ok' 반환",
)
async def health_check_deep(
    db: AsyncSession = Depends(get_db)
):
    """
    (Readiness Probe)
    서비스가 실제 요청을 처리할 준비가 되었는지 확인 (e.g., DB 연결)
    """
    try:
        # 간단한 쿼리를 실행하여 DB 연결 풀 테스트
        await db.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        logger.error(f"Deep health check 실패 (DB 연결 오류): {e}")
        return {"status": "error", "database": "disconnected"}