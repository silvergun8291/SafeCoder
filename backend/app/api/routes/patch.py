import asyncio
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.dependencies import get_scanner_service
from app.models.schemas import ScanRequest, Language
from app.services.patch_service import PatchService
from app.services.scanning.scanner_service import ScannerService
from app.services.llm_service import LLMService
from app.services.rule_generating.rule_generate_service import RuleGenerateService
from app.db.database import async_engine
from app.db.crud import create_piranha_rule, get_piranha_rules_by_cwe

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

        initial_scan = await scanner_service.scan_code(request)
        initial_cwes: list[int] = []
        try:
            initial_cwes = sorted({
                int(getattr(v, "cwe", 0) or 0)
                for v in (getattr(initial_scan, "aggregated_vulnerabilities", []) or [])
                if getattr(v, "cwe", None) is not None
            })
        except Exception:
            initial_cwes = []

        if initial_cwes:
            SessionLocal = async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)
            async with SessionLocal() as session:
                for cwe_id in initial_cwes:
                    cwe_str = f"CWE-{cwe_id}"
                    rules = await get_piranha_rules_by_cwe(session, cwe_str)
                    lang = str(getattr(request, "language", "")).lower()
                    matched = [r for r in (rules or []) if str(getattr(r, "language", "")).lower() == lang]
                    if matched:
                        def _rate(r):
                            s = int(getattr(r, "success_count", 0) or 0)
                            f = int(getattr(r, "fail_count", 0) or 0)
                            total = s + f
                            sr = (s / total) if total > 0 else 0.0
                            sim = float(getattr(r, "validation_similarity", 0.0) or 0.0)
                            return sim, sr, s
                        MIN_SIM = 0.85
                        MIN_SR = 0.6
                        filtered = []
                        for r in matched:
                            sim, sr, s = _rate(r)
                            if sim >= MIN_SIM and sr >= MIN_SR:
                                filtered.append((sim, sr, s, r))
                        filtered.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
                    else:
                        filtered = []
                    if not filtered:
                        continue

                    rule_obj = filtered[0][3]
                    rule_code = getattr(rule_obj, "rule_code", "") or ""
                    if not rule_code:
                        continue

                    try:
                        ns: dict = {}
                        exec(rule_code, ns)
                        if "rule" not in ns:
                            continue

                        try:
                            from polyglot_piranha import execute_piranha, PiranhaArguments, RuleGraph
                            transformed = execute_piranha(PiranhaArguments(
                                code_snippet=request.source_code,
                                language=str(request.language),
                                rule_graph=RuleGraph(rules=[ns["rule"]], edges=[])
                            ))
                            patched_code = transformed[0].content if transformed else request.source_code
                        except ImportError:
                            patched_code = request.source_code

                        if patched_code != request.source_code:
                            try:
                                lang_enum = Language(request.language)
                            except Exception:
                                lang_enum = Language(str(request.language))
                            syntax_ok, _ = PatchService._validate_syntax(patched_code, lang_enum)
                            if not syntax_ok:
                                continue
                            unified_diff = PatchService._unified_diff(
                                request.source_code, patched_code, getattr(request, "filename", None)
                            )

                            try:
                                rescan_req = ScanRequest(
                                    language=request.language,
                                    source_code=patched_code,
                                    filename=request.filename,
                                    options=getattr(request, "options", None),
                                )
                                rescan = await scanner_service.scan_code(rescan_req)
                                final_cwes = sorted({
                                    int(getattr(v, "cwe", 0) or 0)
                                    for v in (getattr(rescan, "aggregated_vulnerabilities", []) or [])
                                    if getattr(v, "cwe", None) is not None
                                })
                                improved = (int(getattr(rescan, "total_vulnerabilities", 0) or 0) <= int(getattr(initial_scan, "total_vulnerabilities", 0) or 0))
                                target_removed = (cwe_id not in set(final_cwes))
                                if not (improved and target_removed):
                                    continue
                            except Exception:
                                final_cwes = []

                            return {
                                "job_id": initial_scan.job_id,
                                "language": str(request.language),
                                "iterations": [],
                                "passed": (len(final_cwes) == 0),
                                "unified_diff": unified_diff,
                                "patched_code": patched_code,
                                "initial_cwes": initial_cwes,
                                "final_cwes": final_cwes,
                                "cwe_code_pairs": {},
                            }
                    except Exception:
                        continue

        use_rag = bool(getattr(getattr(request, "options", None), "use_rag", False))
        result = await service.run_patch(request=request, use_rag=use_rag)

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"패치 처리 실패: {e}")


@router.post(
    "/secure-coding/generate",
    summary="초기 스캔 후 시큐어 코딩 결과만 반환",
    description="룰 생성/적용 및 재스캔/디프 없이, 초기 스캔 정보를 바탕으로 LLM 시큐어 코딩 결과만 반환합니다.",
)
async def secure_generate(
    request: ScanRequest,
    scanner_service: ScannerService = Depends(get_scanner_service),
):
    try:
        initial_scan = await scanner_service.scan_code(request)
        prompt = scanner_service.generate_secure_code_prompt(
            aggregated_vulnerabilities=getattr(initial_scan, "aggregated_vulnerabilities", []) or [],
            source_code=request.source_code,
            language=getattr(request, "language", None),
        )

        llm = LLMService()
        answer = await llm.ask_async(prompt.system_prompt, prompt.user_prompt)
        try:
            lang_enum = Language(request.language)
        except Exception:
            lang_enum = Language(str(request.language))
        fixed_code = PatchService._extract_first_code_block(answer or "", lang_enum) or request.source_code

        return {
            "job_id": getattr(initial_scan, "job_id", None),
            "language": str(request.language),
            "secure_code": fixed_code,
            "initial_vulnerabilities": int(getattr(initial_scan, "total_vulnerabilities", 0) or 0),
            "severity_summary": getattr(initial_scan, "severity_summary", None),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"시큐어 코딩 생성 실패: {e}")


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
            cwe_pairs = result.get("cwe_code_pairs") or {}
            for idx, cwe_id in enumerate(fixed_cwes, 1):
                cwe_str = f"CWE-{cwe_id}"
                logger.info("\n%s", "=" * 80)
                logger.info("[RuleGen] [%d/%d] %s 룰 생성 시작", idx, len(fixed_cwes), cwe_str)
                logger.info("%s", "=" * 80)

                try:
                    pair = cwe_pairs.get(int(cwe_id)) or {}
                    before_src = pair.get("before") or original_code
                    after_src = pair.get("after") or fixed_code

                    gen = rg_service.generate_rule(
                        before_code=before_src,
                        after_code=after_src,
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
                            before_code=before_src,
                            after_code=after_src,
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
