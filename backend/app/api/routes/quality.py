import time
from typing import List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models.schemas import ScanRequest, Language
from app.services.scanning.scanner_service import ScannerService
from app.dependencies import get_scanner_service
from app.services.llm_service import LLMService
from app.utils.code_slicing import slice_function_with_header, find_enclosing_symbol
from app.services import pipeline_prompt_strategies as strat

router = APIRouter()


def _extract_first_code_block(text: str, language: Language) -> str | None:
    import re
    if not text:
        return None
    lang = language.value
    pattern_lang = re.compile(rf"```\s*{re.escape(lang)}\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
    m = pattern_lang.search(text)
    if m:
        return (m.group(1) or '').strip()
    pattern_any = re.compile(r"```\s*\n(.*?)```", re.DOTALL)
    m2 = pattern_any.search(text)
    if m2:
        return (m2.group(1) or '').strip()
    return None


_STRAT_MAP = {
    "one_shot": strat.build_one_shot,
    "one_shot_rag": strat.build_one_shot_with_rag,
    "security_focused_rag": strat.build_security_focused_with_rag,
    "cot_rag": strat.build_cot_with_rag,
    "rci_rag": strat.build_rci_with_rag,
    "combined_rag": strat.build_combined_with_rag,
}


@router.post(
    "/secure-coding/llm-quality/compare",
    summary="여러 LLM 프롬프트 전략(원샷/각+RAG)을 동일 컨텍스트로 실행하여 결과 비교",
    description="스캔 후 첫 번째 취약점이 포함된 함수 슬라이스를 기준 컨텍스트로 삼아, 지정된 전략별로 LLM을 실행하고 결과(프롬프트/응답/코드)를 비교 반환합니다.",
)
async def compare_llm_strategies(
    request: ScanRequest,
    strategies: List[str] = Query(default=[
        "one_shot",
        "one_shot_rag",
        "security_focused_rag",
        "cot_rag",
        "rci_rag",
        "combined_rag",
    ]),
    # 선택 앵커: 특정 CWE 또는 특정 라인 기준으로 슬라이스를 고정
    target_cwe: int | None = Query(default=None, description="이 CWE를 포함한 첫 취약점을 기준으로 비교"),
    target_line: int | None = Query(default=None, description="이 라인이 포함된 함수/메서드를 기준으로 비교"),
    scanner_service: ScannerService = Depends(get_scanner_service),
):
    # 'all' 약어 지원: 전달된 전략 중 'all'이 포함되면 모든 전략으로 확장
    if any(str(s).lower() == "all" for s in strategies):
        strategies = list(_STRAT_MAP.keys())

    # 1) 스캔 실행
    scan_resp = await scanner_service.scan_code(request)
    vulns = scan_resp.aggregated_vulnerabilities or []
    if not vulns:
        raise HTTPException(status_code=400, detail="스캔 결과에 취약점이 없습니다.")

    # 2) 기준 슬라이스: 선택 기준(라인/CWE)으로 앵커 취약점 선택 → 해당 함수 범위를 사용
    language = Language(request.language)
    anchor = vulns[0]
    if target_line is not None:
        # 라인 기준: 가장 가까운(또는 범위 포함) 취약점 선택
        def _dist(v):
            ls = int(getattr(v, "line_start", 0) or 0)
            le = int(getattr(v, "line_end", ls) or ls)
            if ls <= target_line <= le:
                return 0
            return min(abs(target_line - ls), abs(target_line - le))
        anchor = sorted(vulns, key=_dist)[0]
    elif target_cwe is not None:
        for v in vulns:
            try:
                if int(getattr(v, "cwe", 0) or 0) == int(target_cwe):
                    anchor = v
                    break
            except Exception:
                continue

    target_line_val = int(getattr(anchor, "line_start", 1) or 1)
    try:
        s = slice_function_with_header(language, request.source_code, target_line_val)
    except Exception:
        # 파서 실패 시 작은 윈도우
        lines = request.source_code.splitlines()
        i = max(0, target_line_val - 1)
        start = max(0, i - 30)
        end = min(len(lines), i + 30)
        s = "\n".join(lines[start:end])

    # 심볼 범위 추정(프롬프트 메타에 사용)
    sym = find_enclosing_symbol(language, request.source_code, target_line_val)
    if sym:
        func_name, s_line, e_line = sym
    else:
        func_name, s_line, e_line = ("unknown", max(1, target_line - 1), target_line + 1)

    # 그룹 취약점: 같은 함수 범위에 속하는 것들 필터
    group_vulns = []
    for v in vulns:
        ls = int(getattr(v, "line_start", 0) or 0)
        le = int(getattr(v, "line_end", ls) or ls)
        if ls >= s_line and le <= e_line:
            group_vulns.append(v)
    if not group_vulns:
        group_vulns = [first]

    meta = {
        "function_name": func_name,
        "start": s_line,
        "end": e_line,
        "cwes": sorted({int(getattr(v, 'cwe', 0) or 0) for v in group_vulns}),
        "count": len(group_vulns),
    }

    # 3) 전략별 실행
    llm = LLMService()
    results: Dict[str, Any] = {}

    for name in strategies:
        if name not in _STRAT_MAP:
            results[name] = {"error": "unknown strategy"}
            continue
        build = _STRAT_MAP[name]
        try:
            system_prompt, user_prompt = build(
                scanner_service=scanner_service,
                request_source=request.source_code,
                language=language,
                group_vulns=group_vulns,
                meta=meta,
                code_slice=s,
            )
            t0 = time.perf_counter()
            llm_text = llm.ask(system_prompt=system_prompt, user_prompt=user_prompt) or ""
            elapsed = round(time.perf_counter() - t0, 3)
            code = _extract_first_code_block(llm_text, language)
            results[name] = {
                "elapsed_seconds": elapsed,
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "llm_response": llm_text,
                "extracted_code": code,
            }
        except Exception as e:
            results[name] = {"error": str(e)}

    return {
        "job_id": scan_resp.job_id,
        "language": language.value,
        "filename": request.filename,
        "strategies": strategies,
        "meta": meta,
        "code_slice": s,
        "results": results,
    }
