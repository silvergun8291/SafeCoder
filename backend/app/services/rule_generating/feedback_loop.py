"""
피드백 루프 관리자
- 검증 실패 시 재시도
- 피드백 기반 Rule 개선
"""

from typing import Dict, Optional
from .rule_generator import JavaPythonRuleGenerator
from .rule_validator import RuleValidator


class FeedbackLoop:
    """피드백 루프 (최대 3회 재시도)"""

    def __init__(self, llm_client):
        self.generator = JavaPythonRuleGenerator(llm_client)
        self.validator = RuleValidator()
        self.max_attempts = 3

    def generate_with_validation(
            self,
            before_code: str,
            after_code: str,
            ast_result: Dict,
            cwe: str = None,
            language: str = "java"
    ) -> Optional[Dict]:
        """
        검증을 포함한 Rule 생성 (피드백 루프)

        Returns:
            {
                "rule_code": str,
                "name": str,
                "attempts": int,
                "validation_result": Dict
            }
        """

        previous_feedback = None

        for attempt in range(1, self.max_attempts + 1):
            print(f"\n🔄 Attempt {attempt}/{self.max_attempts}")

            # 1. Rule 생성 (이전 피드백 포함)
            rule = self.generator.generate_rule(
                before_code=before_code,
                after_code=after_code,
                ast_result=ast_result,
                cwe=cwe,
                language=language,
                feedback=previous_feedback  # 피드백 전달
            )

            if not rule:
                print(f"❌ Attempt {attempt}: Generation failed")
                continue

            # 2. 검증
            validation = self.validator.validate_rule(
                rule_code=rule["rule_code"],
                before_code=before_code,
                after_code=after_code,
                language=language
            )

            # 3. 성공 시 반환
            if validation["valid"]:
                print(f"✅ Attempt {attempt}: Success!")
                return {
                    **rule,
                    "attempts": attempt,
                    "validation_result": validation
                }

            # 4. 실패 시 피드백 저장
            print(f"⚠️  Attempt {attempt}: Validation failed")
            print(f"   Feedback: {validation['feedback']}")

            previous_feedback = validation["feedback"]

        print(f"❌ All {self.max_attempts} attempts failed")
        return None


class SelfHealingRuleGenerator:
    """자가 치유 Rule 생성기 (피드백 루프 + 재시도)"""

    def __init__(self, llm_client):
        self.feedback_loop = FeedbackLoop(llm_client)

    def generate(
            self,
            before_code: str,
            after_code: str,
            ast_result: Dict,
            cwe: str = None,
            language: str = "java"
    ) -> Optional[Dict]:
        """
        자가 치유 Rule 생성
        """
        print("=" * 80)
        print("🔧 Self-Healing Rule Generation Started")
        print("=" * 80)

        result = self.feedback_loop.generate_with_validation(
            before_code=before_code,
            after_code=after_code,
            ast_result=ast_result,
            cwe=cwe,
            language=language
        )

        if result:
            print("\n" + "=" * 80)
            print(f"✅ Rule Generated Successfully in {result['attempts']} attempt(s)")
            print(f"   Similarity: {result['validation_result']['similarity']:.2%}")
            print("=" * 80)
        else:
            print("\n" + "=" * 80)
            print("❌ Rule Generation Failed After All Attempts")
            print("=" * 80)

        return result
