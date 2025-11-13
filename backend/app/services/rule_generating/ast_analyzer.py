import ast
import javalang
from typing import Dict, List


class JavaASTAnalyzer:
    """Java AST 분석기"""

    @staticmethod
    def parse_java(code: str):
        """Java 코드 파싱"""
        try:
            return javalang.parse.parse(code)
        except Exception as e:
            raise ValueError(f"Java parsing failed: {e}")

    @classmethod
    def extract_imports(cls, tree) -> List[str]:
        """Import 문 추출"""
        imports = []
        if hasattr(tree, 'imports'):
            for imp in tree.imports:
                imports.append(imp.path)
        return imports

    @classmethod
    def extract_methods(cls, tree) -> List[str]:
        """메서드 호출 추출"""
        methods = []
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodInvocation):
                methods.append(node.member)
        return methods

    @classmethod
    def extract_types(cls, tree) -> List[str]:
        """타입 선언 추출"""
        types = []
        for path, node in tree:
            if isinstance(node, javalang.tree.LocalVariableDeclaration):
                if node.type:
                    type_name = node.type.name if hasattr(node.type, 'name') else str(node.type)
                    types.append(type_name)
        return types

    @classmethod
    def extract_variables(cls, tree) -> List[str]:
        """변수명 추출"""
        variables = []
        for path, node in tree:
            if isinstance(node, javalang.tree.VariableDeclarator):
                variables.append(node.name)
        return variables

    @classmethod
    def analyze(cls, before_code: str, after_code: str) -> dict:
        """Java AST diff 분석"""
        try:
            before_tree = cls.parse_java(before_code)
            after_tree = cls.parse_java(after_code)
        except ValueError as e:
            return {
                "error": str(e),
                "changed_types": [],
                "added_methods": [],
                "removed_methods": [],
                "added_imports": [],
                "changed_variables": []
            }

        # Before 분석
        before_imports = set(cls.extract_imports(before_tree))
        before_methods = set(cls.extract_methods(before_tree))
        before_types = set(cls.extract_types(before_tree))
        before_vars = set(cls.extract_variables(before_tree))

        # After 분석
        after_imports = set(cls.extract_imports(after_tree))
        after_methods = set(cls.extract_methods(after_tree))
        after_types = set(cls.extract_types(after_tree))
        after_vars = set(cls.extract_variables(after_tree))

        # Diff 계산
        return {
            "changed_types": [
                                 {"from": t, "to": "?"} for t in before_types - after_types
                             ] + [
                                 {"from": "?", "to": t} for t in after_types - before_types
                             ],
            "added_methods": list(after_methods - before_methods),
            "removed_methods": list(before_methods - after_methods),
            "added_imports": list(after_imports - before_imports),
            "changed_variables": [
                {"from": v, "to": "?"} for v in before_vars - after_vars
            ]
        }


class PythonASTAnalyzer:
    """Python AST 분석기"""

    @staticmethod
    def parse_python(code: str):
        """Python 코드 파싱"""
        try:
            return ast.parse(code)
        except SyntaxError as e:
            raise ValueError(f"Python parsing failed: {e}")

    @classmethod
    def extract_imports(cls, tree) -> List[str]:
        """Import 문 추출"""
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}")
        return imports

    @classmethod
    def extract_function_calls(cls, tree) -> List[str]:
        """함수 호출 추출"""
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    calls.append(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    calls.append(node.func.attr)
        return calls

    @classmethod
    def extract_variables(cls, tree) -> List[str]:
        """변수명 추출"""
        variables = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                variables.append(node.id)
        return variables

    @classmethod
    def analyze(cls, before_code: str, after_code: str) -> dict:
        """Python AST diff 분석"""
        try:
            before_tree = cls.parse_python(before_code)
            after_tree = cls.parse_python(after_code)
        except ValueError as e:
            return {
                "error": str(e),
                "changed_types": [],
                "added_methods": [],
                "removed_methods": [],
                "added_imports": [],
                "changed_variables": []
            }

        # Before 분석
        before_imports = set(cls.extract_imports(before_tree))
        before_calls = set(cls.extract_function_calls(before_tree))
        before_vars = set(cls.extract_variables(before_tree))

        # After 분석
        after_imports = set(cls.extract_imports(after_tree))
        after_calls = set(cls.extract_function_calls(after_tree))
        after_vars = set(cls.extract_variables(after_tree))

        # Diff 계산
        return {
            "changed_types": [],  # Python은 동적 타입
            "added_methods": list(after_calls - before_calls),
            "removed_methods": list(before_calls - after_calls),
            "added_imports": list(after_imports - before_imports),
            "changed_variables": [
                {"from": v, "to": "?"} for v in before_vars - after_vars
            ]
        }


class ASTAnalyzer:
    """통합 AST 분석기"""

    @staticmethod
    def analyze(before_code: str, after_code: str, language: str) -> dict:
        """언어별 AST 분석"""
        if language.lower() == "java":
            return JavaASTAnalyzer.analyze(before_code, after_code)
        elif language.lower() == "python":
            return PythonASTAnalyzer.analyze(before_code, after_code)
        else:
            raise ValueError(f"Unsupported language: {language}")
