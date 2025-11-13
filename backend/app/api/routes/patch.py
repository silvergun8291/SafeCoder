import asyncio
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.dependencies import get_scanner_service
from app.models.schemas import ScanRequest
from app.services.patch_service import PatchService
from app.services.scanning.scanner_service import ScannerService
from app.services.llm_service import LLMService
from app.services.rule_generating.rule_generate_service import RuleGenerateService
from app.db.database import async_engine
from app.db.crud import create_piranha_rule

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
        # use_rag은 요청 바디의 options에서 통일하여 제어
        use_rag = bool(getattr(getattr(request, "options", None), "use_rag", False))
        result = await service.run_patch(request=request, use_rag=use_rag)

        # 비동기 후처리: Diff/Rule 생성/검증/저장 (응답 반환 후 진행)
        asyncio.create_task(_postprocess_rule_generation(request, result))

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"패치 처리 실패: {e}")


async def _postprocess_rule_generation(request: ScanRequest, result: dict) -> None:
    logger = logging.getLogger("app.rulegen")
    try:
        language = str(result.get("language") or request.language)
        original_code = request.source_code
        fixed_code = result.get("patched_code") or ""
        if not fixed_code:
            logger.warning("[RuleGen] patched_code가 비어 있어 후처리를 건너뜁니다.")
            return

        logger.info("%s", "=" * 80)
        logger.info("[RuleGen] 시작 - 언어=%s, 파일=%s", language, getattr(request, "filename", None))
        logger.info("%s", "=" * 80)

        # LLM 어댑터 준비 (RuleGenerateService는 generate(prompt) 스타일 기대)
        class _LLMAdapter:
            def __init__(self, llm: LLMService):
                self._llm = llm

            def generate(self, prompt: str, temperature: float = 0.2):
                # 시스템 프롬프트는 비움, 사용자 프롬프트에 전체 전달
                return self._llm.ask("", prompt) or ""

        llm_adapter = _LLMAdapter(LLMService())
        rg_service = RuleGenerateService(llm_adapter)

        # 고정 대상 CWE 계산: 초기 - 최종 (해결된 CWE만 룰 생성)
        initial_cwes = list(result.get("initial_cwes") or [])
        final_cwes = list(result.get("final_cwes") or [])
        fixed_cwes = [c for c in initial_cwes if c not in set(final_cwes)]

        if not fixed_cwes:
            logger.info("[RuleGen] 생성할 대상 CWE 없음 (모두 미해결 또는 없음) → 종료")
            return

        logger.info("[RuleGen] 대상 CWE=%s개 → %s", len(fixed_cwes), fixed_cwes)

        # DB 세션 준비 (루프 내 재사용)
        SessionLocal = async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)
        async with SessionLocal() as session:
            for idx, cwe_id in enumerate(fixed_cwes, 1):
                cwe_str = f"CWE-{cwe_id}"
                logger.info("\n%s", "=" * 80)
                logger.info("[RuleGen] [%d/%d] %s 룰 생성 시작", idx, len(fixed_cwes), cwe_str)
                logger.info("%s", "=" * 80)

                try:
                    gen = rg_service.generate_rule(
                        before_code=original_code,
                        after_code=fixed_code,
                        cwe=cwe_str,
                        language=language,
                    )

                    if not gen or not gen.get("success"):
                        logger.error("[RuleGen] %s 룰 생성 실패: %s", cwe_str, (gen or {}).get("error"))
                        continue

                    rule = gen.get("rule", {})
                    analysis = gen.get("analysis", {})
                    rule_name = rule.get("name") or f"auto_rule_{cwe_id}"
                    rule_code = rule.get("rule_code") or ""
                    attempts = int(rule.get("attempts") or 1)
                    similarity = (rule.get("validation_result") or {}).get("similarity")

                    logger.info(
                        "[RuleGen] %s 생성 완료: name=%s, attempts=%s, similarity=%s",
                        cwe_str, rule_name, attempts, f"{similarity:.2%}" if isinstance(similarity, (int, float)) else similarity,
                    )

                    try:
                        await create_piranha_rule(
                            db=session,
                            rule_name=rule_name,
                            language=language,
                            rule_code=rule_code,
                            before_code=original_code,
                            after_code=fixed_code,
                            cwe=cwe_str,
                            diff_analysis=analysis.get("diff"),
                            ast_analysis=analysis.get("ast"),
                            validation_similarity=float(similarity) if isinstance(similarity, (int, float)) else None,
                            generation_attempts=attempts,
                        )
                        logger.info("[RuleGen] %s DB 저장 완료: %s", cwe_str, rule_name)
                    except Exception as db_err:
                        logger.error("[RuleGen] %s DB 저장 실패: %s", cwe_str, db_err, exc_info=True)
                except ValueError as ve:
                    logger.warning("[RuleGen] %s 이미 존재: %s", cwe_str, ve)
                except Exception as gen_err:
                    logger.error("[RuleGen] %s 생성 중 예기치 못한 오류: %s", cwe_str, gen_err, exc_info=True)
    except Exception as e:
        logger.error("[RuleGen] 예기치 못한 오류: %s", e, exc_info=True)
