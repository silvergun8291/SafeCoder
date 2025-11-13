import logging

from fastapi import APIRouter, Depends, HTTPException

from app.dependencies import get_scanner_service
from app.models.schemas import ScanRequest, SecureCodePrompt, PromptTechnique
from app.services.rag_service import RAGService
from app.services.scanning.scanner_service import ScannerService

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post(
    "/secure-coding/llm-run",
    summary="스캔 → 프롬프트 생성 → LLM 실행",
    description="소스 코드를 스캔하고, 프롬프트를 생성한 뒤 LLM에 질의하여 응답을 반환합니다.",
)
async def run_llm_secure_fix(
    request: ScanRequest,
    technique: PromptTechnique = PromptTechnique.COMBINED,
    use_rag: bool = False,
    scanner_service: ScannerService = Depends(get_scanner_service),
):
    try:
        rag_service = RAGService(scanner_service)
        result = await rag_service.run_secure_fix(
            request=request,
            technique=technique,
            use_rag=use_rag,
        )
        return result
    except Exception as e:
        logger.error(f"❌ LLM 실행 실패: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="LLM 실행 중 오류가 발생했습니다.")


@router.post(
    "/secure-coding/llm-prompt",
    response_model=SecureCodePrompt,
    summary="스캔 → 프롬프트 생성",
    description="소스 코드를 스캔하고, LLM용 시스템/사용자 프롬프트만 생성하여 반환합니다.",
)
async def build_llm_prompt(
    request: ScanRequest,
    technique: PromptTechnique = PromptTechnique.COMBINED,
    scanner_service: ScannerService = Depends(get_scanner_service),
):
    try:
        scan_response = await scanner_service.scan_code(request)
        prompt = scanner_service.generate_secure_code_prompt(
            source_code=request.source_code,
            language=scan_response.language,
            technique=technique,
        )
        return prompt
    except Exception as e:
        logger.error(f"❌ 프롬프트 생성 실패: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="프롬프트 생성 중 오류가 발생했습니다.")
