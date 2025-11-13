from types import SimpleNamespace

import pytest

from app.models.schemas import Language, SecureCodePrompt
from app.services.patch_service import PatchService
from app.services.rag_service import RAGService


class DummyScannerService:
    def __init__(self, language=Language.PYTHON):
        self.language = language

    async def scan_code(self, request):
        return SimpleNamespace(
            job_id="job-1",
            language=self.language,
            total_vulnerabilities=0,
            severity_summary={},
            scanners_used=["dummy"],
            scanner_errors=[],
            aggregated_vulnerabilities=[],
        )

    def generate_secure_code_prompt(self, aggregated_vulnerabilities, source_code, language, technique=None):
        return SecureCodePrompt(
            system_prompt="You are a secure coding assistant.",
            user_prompt=f"Refactor this {language.value} code securely:\n```{language.value}\n{source_code}\n```",
            vulnerabilities=[],
            metadata={},
            technique=technique,
        )


class DummyLLMService:
    def __init__(self):
        self.called_async = False

    async def ask_async(self, system_prompt: str, user_prompt: str):
        self.called_async = True
        # return a simple code block echo
        return f"```python\n# fixed\nprint('ok')\n```"


@pytest.mark.asyncio
async def test_rag_service_uses_async_llm():
    scanner = DummyScannerService(language=Language.PYTHON)
    llm = DummyLLMService()
    rag = RAGService(scanner_service=scanner, llm_service=llm)

    class Req:
        language = Language.PYTHON
        source_code = "print('x')"
        filename = "a.py"
        options = SimpleNamespace(min_severity=None, timeout=60)

    res = await rag.run_secure_fix(request=Req(), use_rag=False)
    assert llm.called_async is True
    assert "llm_response" in res


def test_patch_service_ast_validation_python_ok():
    ok, err = PatchService._validate_syntax("print('ok')\n", Language.PYTHON)
    assert ok is True
    assert err is None


def test_patch_service_ast_validation_python_fail():
    ok, err = PatchService._validate_syntax("def x(:\n pass\n", Language.PYTHON)
    assert ok is False
    assert isinstance(err, str)


def test_unified_diff_generation():
    original = "print('a')\n"
    fixed = "print('b')\n"
    diff = PatchService._unified_diff(original, fixed, "a.py")
    assert isinstance(diff, str)
    assert "a/a.py" in diff and "b/a.py" in diff
    assert "-print('a')" in diff and "+print('b')" in diff
