# app/api/routes/scan.py
import logging
import asyncio
import docker.errors
from fastapi import APIRouter, Depends, HTTPException
from app.models.schemas import ScanRequest, ScanResponse
from app.services.scanning.scanner_service import ScannerService
from app.core.exceptions import ScannerException
from app.dependencies import get_scanner_service
from pydantic import ValidationError

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post(
    "/secure-coding",
    response_model=ScanResponse,
    summary="시큐어 코딩 스캔 및 패치 요청 (Phase 2)",
    description="소스 코드를 받아 다중 SAST 스캔을 비동기 실행하고 결과를 반환합니다.",
)
async def start_secure_coding_scan(
    request: ScanRequest,
    # 의존성 주입을 통해 서비스 인스턴스를 받음
    scanner_service: ScannerService = Depends(get_scanner_service)
):
    """
    1. ScanRequest로 소스 코드와 언어, 옵션을 받습니다.
    2. ScannerService.scan_code()를 비동기적으로 호출합니다.
    3. 다중 스캐너가 병렬로 실행됩니다.
    4. 결과(ScanResponse)를 집계하여 반환합니다.
    """
    try:
        logger.info(f"스캔 요청 시작: lang={request.language.value}, job_id=pending")
        response = await scanner_service.scan_code(request)
        logger.info(f"스캔 요청 완료: job_id={response.job_id}, vulns={response.total_vulnerabilities}")
        return response
    except asyncio.TimeoutError:
        logger.error("⏱️ 스캔 타임아웃")
        raise ScannerException(detail="스캔 시간 초과")

    except docker.errors.DockerException as e:
        logger.error(f"🐳 Docker 오류: {e}", exc_info=True)
        raise ScannerException(detail="스캐너 컨테이너 실행 실패")

    except ValidationError as e:
        logger.error(f"📋 입력 검증 실패: {e}")
        raise HTTPException(status_code=400, detail="잘못된 입력")

    except Exception as e:
        logger.error(f"❌ 예상치 못한 오류: {e}", exc_info=True)
        raise ScannerException(detail=f"스캔 실패: {type(e).__name__}")