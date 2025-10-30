import logging
from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException

# 'app.exceptions' 이름으로 로거 생성
logger = logging.getLogger("app.exceptions")


# --- 1. 커스텀 예외 정의 ---

class AppException(Exception):
    """애플리케이션 기본 예외"""

    def __init__(self, status_code: int, detail: str, error_code: str = None):
        self.status_code = status_code
        self.detail = detail
        self.error_code = error_code or "APP_EXCEPTION"
        super().__init__(detail)


class ScannerException(AppException):
    """스캐너 실행 관련 예외"""

    def __init__(self, detail: str = "스캐너 실행 중 오류가 발생했습니다."):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
            error_code="SCANNER_ERROR"
        )


class NotFoundException(AppException):
    """리소스를 찾을 수 없을 때 발생하는 예외"""

    def __init__(self, resource: str = "리소"):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{resource}를 찾을 수 없습니다.",
            error_code="NOT_FOUND"
        )


# --- 2. FastAPI 예외 핸들러 등록 ---

async def app_exception_handler(request: Request, exc: AppException):
    """AppException 핸들러 (e.g., ScannerException)"""
    # 커스텀 예외는 '경고' 레벨로 로깅
    logger.warning(
        f"AppException 발생: {exc.error_code} (Status: {exc.status_code}, Detail: {exc.detail})"
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.error_code, "message": exc.detail},
    )


async def http_exception_handler(request: Request, exc: HTTPException):
    """FastAPI HTTPException 핸들러 (e.g., 404 Not Found)"""
    # 일반적인 HTTP 예외도 '경고' 레벨로 로깅
    logger.warning(
        f"HTTPException 발생: (Status: {exc.status_code}, Detail: {exc.detail})"
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": "HTTP_EXCEPTION", "message": exc.detail},
    )


async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"예상치 못한 오류: {exc}", exc_info=True)

    settings = get_settings()

    error_detail = {
        "error": "INTERNAL_SERVER_ERROR",
        "message": "서버 내부 오류가 발생했습니다.",
    }

    # ⭐ 개발 환경에서 상세 정보 제공
    if settings.APP_ENV == "development":
        error_detail["detail"] = str(exc)
        error_detail["type"] = type(exc).__name__

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_detail,
    )
