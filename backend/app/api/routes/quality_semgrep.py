import time
from typing import List, Dict, Any, Optional

from fastapi import APIRouter, HTTPException, Query

from app.models.schemas import Language, SemgrepAutofixRuleRequest
from app.services.semgrep_rule_service import SemgrepRuleService

router = APIRouter()


# 전략 정의:
# - default: 기본 설정(top_k=3, 슬라이스 자동)
# - cwe_scoped: target_cwes를 제공하여 해당 취약점 범위로 한정
# - slices_only: original_slice/fixed_slice만 사용(호출자가 제공해야 정확)
# - full_diff_only: 슬라이스 제공 없이 전체 diff 기반 생성(서비스가 내부 슬라이스 추정은 수행)
_STRATS = [
    "default",
    "cwe_scoped",
    "slices_only",
    "full_diff_only",
]

# 프롬프트 기법(semgrep rule 전용): 요청에 따라 3가지만 제공
_PROMPT_STRATS = [
    "one_shot_rag",  # alias: oneshot
    "cot_rag",
    "combined_rag",
]


def _make_req(
    language: Language,
    filename: Optional[str],
    original_code: str,
    fixed_code: str,
    strategy: str,
    target_cwes: Optional[List[int]] = None,
    original_slice: Optional[str] = None,
    fixed_slice: Optional[str] = None,
) -> SemgrepAutofixRuleRequest:
    # slices_only 전략: 슬라이스가 없으면 에러로 처리
    if strategy == "slices_only" and (not original_slice or not fixed_slice):
        raise HTTPException(status_code=400, detail="slices_only 전략은 original_slice/fixed_slice가 필요합니다.")

    # full_diff_only 전략: 슬라이스를 강제로 제거
    if strategy == "full_diff_only":
        original_slice = None
        fixed_slice = None

    # cwe_scoped는 target_cwes가 있어야 효과. 없으면 default와 동일하게 동작
    req = SemgrepAutofixRuleRequest(
        language=language,
        filename=filename,
        original_code=original_code,
        fixed_code=fixed_code,
        original_slice=original_slice,
        fixed_slice=fixed_slice,
    )
    # target_cwes를 동적으로 부여하기 위해 속성 주입(모델에 선택 필드로 정의되어 있지 않음 → 동적 속성 부여)
    if target_cwes and strategy in ("cwe_scoped", "default"):
        setattr(req, "target_cwes", [int(c) for c in target_cwes])
    return req


@router.post(
    "/secure-coding/semgrep-quality/compare",
    summary="여러 전략으로 Semgrep Autofix Rule 생성 품질 비교",
    description=(
        "original_code/fixed_code(또는 슬라이스)를 JSON Body로 입력 받아 다양한 전략으로 Semgrep autofix 룰을 생성하고, "
        "생성된 YAML과 검증/스캔 로그, RAG 참조를 비교합니다."
    ),
)
async def compare_semgrep_rule_strategies(
    request: SemgrepAutofixRuleRequest,
    strategies: List[str] = Query(default=_STRATS),
    prompt_strategies: List[str] = Query(default=_PROMPT_STRATS),
    target_cwes: Optional[List[int]] = Query(default=None),
):
    # alias & 'all' 약어 지원
    if any(str(s).lower() == "all" for s in strategies):
        strategies = list(_STRATS)
    # normalize prompt aliases
    normalized_ps: List[str] = []
    for ps in prompt_strategies:
        psl = str(ps).lower()
        if psl == "all":
            normalized_ps = list(_PROMPT_STRATS)
            break
        if psl in ("oneshot", "one_shot"):
            normalized_ps.append("one_shot_rag")
        else:
            normalized_ps.append(ps)
    prompt_strategies = normalized_ps
    # 전략 유효성
    for s in strategies:
        if s not in _STRATS:
            raise HTTPException(status_code=400, detail=f"unknown strategy: {s}")
    for ps in prompt_strategies:
        if ps not in _PROMPT_STRATS:
            raise HTTPException(status_code=400, detail=f"unknown prompt_strategy: {ps}")

    service = SemgrepRuleService()
    results: Dict[str, Any] = {}

    for s in strategies:
        results[s] = {}
        for ps in prompt_strategies:
            try:
                req = _make_req(
                    language=request.language,
                    filename=request.filename,
                    original_code=request.original_code,
                    fixed_code=request.fixed_code,
                    strategy=s,
                    target_cwes=target_cwes,
                    original_slice=request.original_slice,
                    fixed_slice=request.fixed_slice,
                )
                t0 = time.perf_counter()
                resp = service.generate_autofix_rule(req, prompt_strategy=ps)
                elapsed = round(time.perf_counter() - t0, 3)
                results[s][ps] = {
                    "elapsed_seconds": elapsed,
                    "rule_yaml": resp.rule_yaml,
                    "reasoning": resp.reasoning,
                    "retrieved_context": resp.retrieved_context,
                }
            except HTTPException as e:
                raise e
            except Exception as e:
                results[s][ps] = {"error": str(e)}

    return {
        "language": request.language.value,
        "filename": request.filename,
        "strategies": strategies,
        "prompt_strategies": prompt_strategies,
        "target_cwes": target_cwes,
        "has_slices": bool(request.original_slice and request.fixed_slice),
        "results": results,
    }
