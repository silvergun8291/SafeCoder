from typing import List, Dict, Any, Tuple

from app.models.schemas import Language, PromptTechnique, SecureCodePrompt
from app.services.rag_service import RAGService
from app.services.scanning.scanner_service import ScannerService


# Prompt diet: concise core rules and CWE-specific adds
COMMON_RULES: List[str] = [
    "Preserve functionality. Fix security issues without breaking the code.",
    "LOGGING: Do NOT log exception details (message/stack trace) to console/users. Log ONLY a UUID errorId.",
    "SECRETS: NEVER hardcode secrets/keys/tokens. Use System.getenv() even in main/test methods.",
    "CRYPTO: Use 'AES/GCM/NoPadding' for encryption. Use SHA-256 for hashing.",
    "BASE64: Base64 is NOT encryption. Do not use it to hide secrets.",
    "INPUT: Validate all external inputs against a strict allowlist (regex).",
    # "EXEC: Use ProcessBuilder with argument arrays. Never use string concatenation for commands.",
    # "HEX: Use String.format(\"%02x\", b) for hex conversion. Avoid Integer.toHexString.",
]

CWE_SPECIFIC_RULES: Dict[int, List[str]] = {
    78: ["Use API-based execution (ProcessBuilder) with arrays. NO shell redirection."],
    89: ["Use PreparedStatement with bind variables ONLY."],
    22: ["Validate paths against an allowlist. Reject '..' or '/' in filenames."],
    798: ["Replace hardcoded secrets with System.getenv(\"KEY_NAME\")."],
    327: ["Use AES-GCM. Ensure IV is random (SecureRandom) and unique."],
    20: ["Reject invalid input immediately. Do not attempt to sanitize malicious input."],
}


def _build_dynamic_rules(group_vulns: List[Any]) -> str:
    """필요한 규칙만 골라서 주입 (토큰 절약)"""
    selected_rules: List[str] = list(COMMON_RULES)

    cwe_ids: set[int] = set()
    for v in (group_vulns or []):
        cwe = getattr(v, "cwe", None)
        if cwe:
            try:
                cwe_ids.add(int(cwe))
            except Exception:
                pass

    if 0 in cwe_ids:
        cwe_ids.add(327)

    for cwe in cwe_ids:
        if cwe in CWE_SPECIFIC_RULES:
            selected_rules.extend(CWE_SPECIFIC_RULES[cwe])

    unique_rules = sorted(list(set(selected_rules)), key=selected_rules.index)
    return "### SECURITY RULES (STRICT COMPLIANCE REQUIRED)\n" + "\n".join(f"- {r}" for r in unique_rules)


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
    dynamic_rules = _build_dynamic_rules(group_vulns)
    system_prompt = f"{base.system_prompt or ''}\n\n{dynamic_rules}" + (rag_section or "")

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
