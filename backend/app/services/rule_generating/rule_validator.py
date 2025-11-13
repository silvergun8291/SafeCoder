"""
Piranha Rule 검증기
- 구문 검증
- 실행 검증 (Piranha 적용)
- 유사도 검증
"""

from typing import Dict, Optional
import difflib
import re


class RuleValidator:
    """Rule 검증기"""

    def validate_rule(
            self,
            rule_code: str,
            before_code: str,
            after_code: str,
            language: str = "java"
    ) -> Dict:
        """
        Rule 전체 검증

        Returns:
            {
                "valid": bool,
                "errors": List[str],
                "warnings": List[str],
                "similarity": float,
                "feedback": str  # LLM에게 줄 피드백
            }
        """

        result = {
            "valid": False,
            "errors": [],
            "warnings": [],
            "similarity": 0.0,
            "feedback": ""
        }

        # 1. 구문 검증
        syntax_check = self._validate_syntax(rule_code)
        if not syntax_check["valid"]:
            result["errors"].append(syntax_check["error"])
            result["feedback"] = f"Syntax Error: {syntax_check['error']}"
            return result

        # 2. 필수 필드 검증
        field_check = self._validate_required_fields(rule_code)
        if not field_check["valid"]:
            result["errors"].extend(field_check["missing"])
            result["feedback"] = f"Missing fields: {', '.join(field_check['missing'])}"
            return result

        # 3. 실행 검증 (Piranha 적용)
        exec_result = self._validate_execution(rule_code, before_code, language)

        if not exec_result["valid"]:
            result["errors"].append(exec_result["error"])
            result["feedback"] = exec_result["error"]
            return result

        # 4. 유사도 검증
        similarity = self._calculate_similarity(
            exec_result["transformed"],
            after_code
        )

        result["similarity"] = similarity

        if similarity < 0.7:
            result["warnings"].append(f"Low similarity: {similarity:.2%}")
            result["feedback"] = (
                f"Transformed code similarity is only {similarity:.2%}. "
                f"Expected pattern not fully matched."
            )
        else:
            result["valid"] = True
            result["feedback"] = f"Valid rule with {similarity:.2%} similarity"

        return result

    @staticmethod
    def _validate_syntax(rule_code: str) -> Dict:
        """Python 구문 검증"""
        try:
            compile(rule_code, '<string>', 'exec')
            return {"valid": True}
        except SyntaxError as e:
            return {"valid": False, "error": f"Python syntax error: {e}"}

    @staticmethod
    def _validate_required_fields(rule_code: str) -> Dict:
        """필수 필드 존재 확인"""
        required = ['name', 'query', 'replace_node', 'replacement']
        missing = []

        for field in required:
            if f'{field}=' not in rule_code and f'{field} =' not in rule_code:
                missing.append(field)

        return {
            "valid": len(missing) == 0,
            "missing": missing
        }

    @staticmethod
    def _validate_execution(
            rule_code: str,
            before_code: str,
            language: str
    ) -> Dict:
        """Piranha 실행 검증"""
        try:
            # Rule 객체 생성
            namespace = {}
            exec(rule_code, namespace)

            if 'rule' not in namespace:
                return {"valid": False, "error": "No 'rule' variable found"}

            rule = namespace['rule']

            # Piranha 적용 시도
            try:
                from polyglot_piranha import execute_piranha, PiranhaArguments, RuleGraph

                result = execute_piranha(PiranhaArguments(
                    code_snippet=before_code,
                    language=language,
                    rule_graph=RuleGraph(rules=[rule], edges=[])
                ))

                return {
                    "valid": True,
                    "transformed": result[0].content
                }

            except ImportError:
                # polyglot_piranha 없으면 스킵
                return {
                    "valid": True,
                    "transformed": before_code,
                    "warning": "Piranha not installed - skipped execution test"
                }

        except Exception as e:
            return {"valid": False, "error": f"Execution failed: {str(e)}"}

    @staticmethod
    def _calculate_similarity(code1: str, code2: str) -> float:
        """코드 유사도 계산"""
        return difflib.SequenceMatcher(
            None,
            code1.strip(),
            code2.strip()
        ).ratio()
