# app/api/routes/scan.py
import asyncio
import logging

import docker.errors
from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError

from app.core.exceptions import ScannerException
from app.dependencies import get_scanner_service
from app.models.schemas import (
    ScanRequest, ScanResponse, LLMFixContext,
    SecureCodePrompt, PromptTechnique
)
from app.services.scanning.scanner_service import ScannerService

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


# 새로운 LLM 프롬프트 생성 엔드포인트 추가
@router.post(
    "/secure-coding/llm-context",
    response_model=LLMFixContext,
    summary="LLM 시큐어 코딩 프롬프트 생성",
    description="스캔 결과를 LLM이 이해하기 쉬운 형태로 변환하여 반환합니다.",
)
async def get_llm_fix_context(
        request: ScanRequest,
        scanner_service: ScannerService = Depends(get_scanner_service)
):
    """
    1. 소스 코드를 스캔합니다.
    2. 집계된 취약점을 LLM 최적화 형태로 변환합니다.
    3. LLM이 시큐어 코딩을 수행할 수 있는 프롬프트 컨텍스트를 반환합니다.
    """
    try:
        logger.info(f"LLM 컨텍스트 생성 시작: lang={request.language.value}")

        # 1. 스캔 실행
        scan_response = await scanner_service.scan_code(request)

        # 2. LLM 컨텍스트 생성
        llm_context = ScannerService.prepare_llm_fix_context(
            aggregated_vulnerabilities=scan_response.aggregated_vulnerabilities,
            source_code=request.source_code,
            language=request.language,
            include_recommendations=True
        )

        logger.info(f"LLM 컨텍스트 생성 완료: job_id={scan_response.job_id}, vulns={llm_context['total_vulnerabilities']}")

        return LLMFixContext(**llm_context)

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
        raise ScannerException(detail=f"LLM 컨텍스트 생성 실패: {type(e).__name__}")


@router.post(
    "/secure-coding/prompt",
    response_model=SecureCodePrompt,
    summary="고급 시큐어 코딩 프롬프트 생성 (Prompt Engineering)",
    description="Security-Focused, Chain-of-Thought, RCI 기법을 적용한 최적화된 LLM 프롬프트를 생성합니다.",
)
async def generate_secure_code_prompt(
    request: ScanRequest,
    technique: PromptTechnique = PromptTechnique.COMBINED,
    include_framework_context: bool = True,
    scanner_service: ScannerService = Depends(get_scanner_service)
):
    """
    프롬프트 엔지니어링 기법을 적용한 시큐어 코딩 프롬프트 생성

    - Security-Focused: 56% 취약점 감소 효과
    - Chain-of-Thought: 단계별 추론으로 정확도 향상
    - RCI: 자기 비판을 통한 반복적 개선
    - Combined: 모든 기법 통합 (권장)
    """
    try:
        logger.info(f"고급 프롬프트 생성 시작: lang={request.language.value}, technique={technique.value}")

        # 1. 스캔 실행
        scan_response = await scanner_service.scan_code(request)

        # 2. 프롬프트 엔지니어링 기법 적용
        secure_prompt = ScannerService.generate_secure_code_prompt(
            aggregated_vulnerabilities=scan_response.aggregated_vulnerabilities,
            source_code=request.source_code,
            language=request.language,
            technique=technique,
        )

        logger.info(
            f"프롬프트 생성 완료: job_id={scan_response.job_id}, "
            f"technique={technique.value}, vulns={secure_prompt.metadata['total_vulnerabilities']}"
        )

        return secure_prompt

    except Exception as e:
        logger.error(f"❌ 프롬프트 생성 실패: {e}", exc_info=True)
        raise ScannerException(detail=f"프롬프트 생성 실패: {type(e).__name__}")
