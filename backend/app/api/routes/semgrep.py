from fastapi import APIRouter, HTTPException

from app.models.schemas import SemgrepAutofixRuleRequest, SemgrepAutofixRuleResponse
from app.services.semgrep_rule_service import SemgrepRuleService

router = APIRouter()


@router.post(
    "/secure-coding/semgrep/autofix-rule",
    response_model=SemgrepAutofixRuleResponse,
    summary="원본/수정 코드를 기반으로 Semgrep Autofix Rule 생성",
    description="LLM과 RAG(semgrep_rule_db)를 활용하여 유효한 Semgrep Autofix 룰 YAML을 생성합니다.",
)
def generate_semgrep_autofix_rule(request: SemgrepAutofixRuleRequest) -> SemgrepAutofixRuleResponse:
    try:
        service = SemgrepRuleService()
        return service.generate_autofix_rule(request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"룰 생성 실패: {e}")
