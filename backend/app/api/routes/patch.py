from fastapi import APIRouter, Depends, HTTPException

from app.models.schemas import ScanRequest
from app.services.scanning.scanner_service import ScannerService
from app.services.patch_service import PatchService
from app.dependencies import get_scanner_service

router = APIRouter()


@router.post(
    "/secure-coding/patch",
    summary="LLM 시큐어코딩 → AST 검증 → 재스캔 루프 → 디프 → 패치 적용",
    description="원본 코드를 LLM으로 시큐어 코딩하고 AST 검증 및 스캐너 재스캔을 통과하면 유니파이드 디프를 생성하고 패치를 적용한 최종 코드를 반환합니다.",
)
async def secure_patch(
    request: ScanRequest,
    scanner_service: ScannerService = Depends(get_scanner_service),
):
    try:
        service = PatchService(scanner_service)
        result = await service.run_patch(request=request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"패치 처리 실패: {e}")
