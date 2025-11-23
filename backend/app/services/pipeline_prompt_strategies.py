from typing import List, Dict, Any, Tuple

from app.models.schemas import Language, PromptTechnique, SecureCodePrompt
from app.services.rag_service import RAGService
from app.services.scanning.scanner_service import ScannerService

HARD_RULES = (
    "[SECURITY HARD RULES]\n"
    "- Never use shell invocation for command execution (no /bin/sh, cmd.exe, or single-string exec).\n"
    "- Use API-based execution with argument array (e.g., Java ProcessBuilder(\"cmd\", arg) or Python subprocess.run([...], shell=False)).\n"
    "- Do NOT concatenate user input into commands. No string + variable to build commands.\n"
    "- Enforce strict allowlist validation for all external inputs (regex or explicit set). Reject invalid inputs.\n"
    "- Disallow relative paths (./, ../). Use only allowlisted absolute commands/paths.\n"
    "- Principle of least privilege: do not escalate privileges; do not add dangerous flags.\n"
    "- Preserve original functionality while applying the fixes.\n"
    "- Do NOT log exception names, stack traces, or raw error messages in production logs.\n"
    "- Log only an opaque errorId for correlation; send full details to a secure error collector (e.g., APM/Sentry).\n"
    "- Allow stack traces only in debug/development mode.\n"
    "- Never include sensitive data in logs (tokens, keys, credentials, PII, headers, request/response bodies).\n"
    "- Regular Expressions: enforce strict validation rules.\n"
    "  - Always anchor with ^...$ to match the entire input.\n"
    "  - Specify explicit length limits (e.g., {1,64}).\n"
    "  - Use a minimal, purpose-specific allowlist character set (e.g., [A-Za-z0-9._-]).\n"
    "  - Forbid leading '-' (CLI option injection) and leading '.' (hidden/relative).\n"
    "  - Forbid '..' and any path separators ('/' or '\\').\n"
    "  - Prefer fixed allowlists (Set/Enum) over regex when feasible.\n"
)


def _build_base_prompt(
    scanner_service: ScannerService,
    request_source: str,
    language: Language,
    group_vulns: List[Any],
    technique: PromptTechnique,
) -> SecureCodePrompt:
    return scanner_service.generate_secure_code_prompt(
        aggregated_vulnerabilities=group_vulns,
        source_code=request_source,
        language=language,
        technique=technique,
    )


def _augment_with_rag(
    rag_service: RAGService,
    language: Language,
    group_vulns: List[Any],
) -> str:
    try:
        code_docs_all: List[Dict[str, Any]] = []
        kisa_docs_all: List[Dict[str, Any]] = []
        owasp_docs_all: List[Dict[str, Any]] = []
        for v in (group_vulns or []):
            cwe_id = str(getattr(v, "cwe", "") or "").strip()
            desc = getattr(v, "description", "") or ""
            code_snippet = getattr(v, "code_snippet", "") or ""
            if not cwe_id:
                continue
            code_docs_all += rag_service._retrieve_code_examples(
                language=language.value,
                cwe_id=cwe_id,
                description=desc,
                code_snippet=code_snippet,
                top_k=1,
            )
            kisa_docs_all += rag_service._retrieve_text_guidelines(
                query=(f"CWE-{cwe_id} {desc}".strip()), db="kisa", top_k=1
            )
            owasp_docs_all += rag_service._retrieve_text_guidelines(
                query=(desc or f"CWE-{cwe_id}"), db="owasp", top_k=1
            )
        directive = (
            "IMPORTANT: Strictly follow the retrieved security guidelines and secure code examples. "
            "Priority: KISA > OWASP > Code Examples. Avoid unsafe dynamic execution and hard-coded secrets; "
            "validate and allowlist external inputs; ensure compliance with OWASP/CWE best practices."
        )
        return "\n\n" + directive + "\n\n" + RAGService._format_rag_sections(
            code_docs_all, kisa_docs_all, owasp_docs_all
        )
    except Exception:
        return ""


def _compose_prompts(
    base: SecureCodePrompt,
    use_rag: bool,
    rag_service: RAGService | None,
    language: Language,
    group_vulns: List[Any],
    meta: Dict[str, Any],
    code_slice: str,
) -> Tuple[str, str]:
    # system prompt
    rag_section = ""
    if use_rag and rag_service is not None:
        rag_section = _augment_with_rag(rag_service, language, group_vulns)
    system_prompt = f"{base.system_prompt or ''}\n\n{HARD_RULES}" + (rag_section or "")

    # user prompt
    cwe_list = ", ".join(f"CWE-{c}" for c in meta.get("cwes", [])) or "N/A"
    user_prompt = (
        (base.user_prompt + "\n\n" if base.user_prompt else "")
        + f"Language: {language.value}\n"
        + f"Target Function: {meta.get('function_name','unknown')} (lines {meta.get('start')}..{meta.get('end')})\n"
        + f"Vulnerabilities to fix (strict scope): {cwe_list}\n\n"
        + f"```{language.value}\n{code_slice}\n```"
    )
    return system_prompt, user_prompt


# 1) 원샷(라벨용: one_shot)
def build_one_shot(
    scanner_service: ScannerService,
    request_source: str,
    language: Language,
    group_vulns: List[Any],
    meta: Dict[str, Any],
    code_slice: str,
) -> Tuple[str, str]:
    base = _build_base_prompt(scanner_service, request_source, language, group_vulns, PromptTechnique.SECURITY_FOCUSED)
    return _compose_prompts(base, False, None, language, group_vulns, meta, code_slice)


# 2) 원샷 + RAG
def build_one_shot_with_rag(
    scanner_service: ScannerService,
    request_source: str,
    language: Language,
    group_vulns: List[Any],
    meta: Dict[str, Any],
    code_slice: str,
) -> Tuple[str, str]:
    base = _build_base_prompt(scanner_service, request_source, language, group_vulns, PromptTechnique.SECURITY_FOCUSED)
    rag = RAGService(scanner_service)
    return _compose_prompts(base, True, rag, language, group_vulns, meta, code_slice)


# 3) _generate_security_focused_prompt + RAG
def build_security_focused_with_rag(
    scanner_service: ScannerService,
    request_source: str,
    language: Language,
    group_vulns: List[Any],
    meta: Dict[str, Any],
    code_slice: str,
) -> Tuple[str, str]:
    base = _build_base_prompt(scanner_service, request_source, language, group_vulns, PromptTechnique.SECURITY_FOCUSED)
    rag = RAGService(scanner_service)
    return _compose_prompts(base, True, rag, language, group_vulns, meta, code_slice)


# 4) _generate_cot_prompt + RAG
def build_cot_with_rag(
    scanner_service: ScannerService,
    request_source: str,
    language: Language,
    group_vulns: List[Any],
    meta: Dict[str, Any],
    code_slice: str,
) -> Tuple[str, str]:
    base = _build_base_prompt(scanner_service, request_source, language, group_vulns, PromptTechnique.CHAIN_OF_THOUGHT)
    rag = RAGService(scanner_service)
    return _compose_prompts(base, True, rag, language, group_vulns, meta, code_slice)


# 5) _generate_rci_prompt + RAG
def build_rci_with_rag(
    scanner_service: ScannerService,
    request_source: str,
    language: Language,
    group_vulns: List[Any],
    meta: Dict[str, Any],
    code_slice: str,
) -> Tuple[str, str]:
    base = _build_base_prompt(scanner_service, request_source, language, group_vulns, PromptTechnique.RCI)
    rag = RAGService(scanner_service)
    return _compose_prompts(base, True, rag, language, group_vulns, meta, code_slice)


# 6) _generate_combined_prompt + RAG
def build_combined_with_rag(
    scanner_service: ScannerService,
    request_source: str,
    language: Language,
    group_vulns: List[Any],
    meta: Dict[str, Any],
    code_slice: str,
) -> Tuple[str, str]:
    base = _build_base_prompt(scanner_service, request_source, language, group_vulns, PromptTechnique.COMBINED)
    rag = RAGService(scanner_service)
    return _compose_prompts(base, True, rag, language, group_vulns, meta, code_slice)
