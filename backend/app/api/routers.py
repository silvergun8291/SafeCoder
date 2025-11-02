from fastapi import APIRouter

from app.api.routes import health, scan
# from app.api.routes import patch, rag # 추후 구현

api_router = APIRouter()

# 헬스 체크 라우터
api_router.include_router(
    health.router,
    prefix="/health",  # ⬅️ /api/health/shallow, /api/health/deep
    tags=["Health"]
)

# 스캔 라우터
api_router.include_router(
    scan.router,
    prefix="",  # ⬅️ /api/secure-coding
    tags=["Secure Coding"]
)