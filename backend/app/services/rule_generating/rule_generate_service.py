"""
Piranha Rule 생성 서비스

사용법:
    service = RuleGenerateService(llm_client)
    result = service.generate_rule(before_code, after_code, cwe, language)
"""

from typing import Dict, Optional
import logging

from .diff_analyzer import DiffAnalyzer
from .ast_analyzer import ASTAnalyzer
from .feedback_loop import SelfHealingRuleGenerator


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RuleGenerateService:
    """Piranha Rule 자동 생성 서비스"""

    def __init__(self, llm_client):
        """
        Args:
            llm_client: LLM 클라이언트
        """
        self.llm = llm_client
        self.rule_generator = SelfHealingRuleGenerator(llm_client)
        logger.info("RuleGenerateService initialized")

    def generate_rule(
        self,
        before_code: str,
        after_code: str,
        cwe: str = None,
        language: str = "java"
    ) -> Dict:
        """
        Piranha Rule 생성

        Args:
            before_code: 취약한 원본 코드
            after_code: 보안 패치된 코드
            cwe: CWE 번호
            language: 언어

        Returns:
            {
                "success": bool,
                "rule": {
                    "rule_code": str,
                    "name": str,
                    "attempts": int,
                    "validation_result": Dict
                },
                "analysis": {
                    "diff": Dict,
                    "ast": Dict
                },
                "error": str (optional)
            }
        """

        logger.info(f"Starting rule generation for {cwe} ({language})")

        try:
            # Step 1: Diff 분석
            logger.info("Step 1: Analyzing diff...")
            diff_result = DiffAnalyzer.analyze(before_code, after_code)
            logger.info(
                f"  Changed: {diff_result['changed_lines']} lines "
                f"(+{diff_result['added_lines']}, -{diff_result['removed_lines']})"
            )

            # Step 2: AST 분석
            logger.info("Step 2: Analyzing AST...")
            ast_result = ASTAnalyzer.analyze(before_code, after_code, language)
            logger.info(
                f"  Methods: +{len(ast_result['added_methods'])}, "
                f"-{len(ast_result['removed_methods'])}"
            )

            # Step 3: Rule 생성 (검증 + 피드백 루프)
            logger.info("Step 3: Generating rule...")
            rule = self.rule_generator.generate(
                before_code=before_code,
                after_code=after_code,
                ast_result=ast_result,
                cwe=cwe,
                language=language
            )

            if not rule:
                logger.error("Rule generation failed")
                return {
                    "success": False,
                    "error": "Rule generation failed after all retry attempts",
                    "analysis": {
                        "diff": diff_result,
                        "ast": ast_result
                    }
                }

            # 성공
            logger.info(
                f"✅ Success in {rule['attempts']} attempt(s), "
                f"similarity: {rule['validation_result']['similarity']:.2%}"
            )

            return {
                "success": True,
                "rule": rule,
                "analysis": {
                    "diff": diff_result,
                    "ast": ast_result
                }
            }

        except Exception as e:
            logger.exception("Unexpected error")
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}"
            }

    def generate_rule_batch(
        self,
        code_pairs: list,
        language: str = "java"
    ) -> list:
        """
        배치 처리

        Args:
            code_pairs: [{"before": str, "after": str, "cwe": str}, ...]

        Returns:
            [result1, result2, ...]
        """
        logger.info(f"Batch: {len(code_pairs)} pairs")

        results = []
        for i, pair in enumerate(code_pairs, 1):
            logger.info(f"Processing {i}/{len(code_pairs)}...")

            result = self.generate_rule(
                before_code=pair["before"],
                after_code=pair["after"],
                cwe=pair.get("cwe"),
                language=language
            )
            results.append(result)

        success = sum(1 for r in results if r["success"])
        logger.info(f"Batch completed: {success}/{len(code_pairs)} succeeded")

        return results

    def analyze_only(
        self,
        before_code: str,
        after_code: str,
        language: str = "java"
    ) -> Dict:
        """
        분석만 수행 (Rule 생성 안 함)

        Returns:
            {"diff": Dict, "ast": Dict}
        """
        diff_result = DiffAnalyzer.analyze(before_code, after_code)
        ast_result = ASTAnalyzer.analyze(before_code, after_code, language)

        return {
            "diff": diff_result,
            "ast": ast_result
        }


def create_rule_service(llm_client) -> RuleGenerateService:
    """서비스 인스턴스 생성"""
    return RuleGenerateService(llm_client)
