import re
import time
import asyncio
import logging
import os
from datetime import datetime
import json
try:
    import yaml  # PyYAML for robust YAML merging
except Exception:
    yaml = None  # fallback to regex merger
from typing import Optional, List, Dict, Any, Tuple, DefaultDict
from collections import defaultdict
from fastapi import APIRouter, Depends, HTTPException

from app.models.schemas import ScanRequest, PromptTechnique
from app.services.scanning.scanner_service import ScannerService
from app.services.rag_service import RAGService
from app.services.patch_service import PatchService
from app.dependencies import get_scanner_service
from app.models.schemas import Language
from app.utils.code_slicing import slice_function_with_header, find_enclosing_symbol
from app.services.llm_service import LLMService

router = APIRouter()
logger = logging.getLogger("pipeline")
# Ensure logger outputs to console even if not configured globally
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s - %(message)s'))
    logger.addHandler(_handler)
logger.setLevel(logging.INFO)
logger.propagate = True


def _extract_first_code_block(text: str, language: Language) -> Optional[str]:
    if not text:
        return None
    # try ```<lang> code ```
    lang = language.value
    pattern_lang = re.compile(rf"```\s*{re.escape(lang)}\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
    m = pattern_lang.search(text)
    if m:
        return m.group(1).strip()
    # fallback: first fenced block
    pattern_any = re.compile(r"```\s*\n(.*?)```", re.DOTALL)
    m2 = pattern_any.search(text)
    if m2:
        return m2.group(1).strip()
    return None


@router.post(
    "/secure-coding/pipeline/scan-llm-autofix-rule",
    summary="스캔 → LLM 시큐어코딩 → AST 검증 → 재스캔 루프 → 디프 → 패치 적용",
    description=(
        "소스 코드를 스캔하고, LLM으로 전체 코드를 시큐어 코딩합니다. AST 유효성 검사와 언어별 스캐너 재스캔(Bandit/Semgrep 또는 Horusec/Semgrep) 루프를 통과하면, "
        "difflib 유니파이드 디프를 생성하고 whatthepatch로 원본에 패치를 적용하여 최종 코드를 반환합니다."
    ),
)
@router.post(
    "/secure-coding/pipeline/scan-llm-patch",
    summary="스캔 → LLM 시큐어코딩 → AST 검증 → 재스캔 루프 → 디프 → 패치 적용",
    description=(
        "소스 코드를 스캔하고, LLM으로 전체 코드를 시큐어 코딩합니다. AST 유효성 검사와 언어별 스캐너 재스캔(Bandit/Semgrep 또는 Horusec/Semgrep) 루프를 통과하면, "
        "difflib 유니파이드 디프를 생성하고 whatthepatch로 원본에 패치를 적용하여 최종 코드를 반환합니다."
    ),
)
async def scan_llm_autofix_rule(
    request: ScanRequest,
    technique: PromptTechnique = PromptTechnique.COMBINED,
    use_rag: bool = True,
    # 기존 파라미터는 호환을 위해 유지
    strategy: Optional[str] = None,
    rule_strategy: Optional[str] = None,
    mode: str = "combined",
    rule_mode: str = "single",
    llm_concurrency: int = 3,
    rule_concurrency: int = 3,
    log_verbose: bool = False,
    scanner_service: ScannerService = Depends(get_scanner_service),
):
    try:
        timings: Dict[str, float] = {}
        t0 = time.perf_counter()

        # 0) 스캐너 제한: 바디의 options.specific_scanners만 사용합니다.
        # 값이 없거나 빈 배열이면 해당 언어의 모든 스캐너를 사용합니다.

        # 0.5) 전략 약어 해석 (전달 시 technique/use_rag를 오버라이드)
        if isinstance(strategy, str):
            s = strategy.strip().lower()
            if s == "combined_rag":
                technique = PromptTechnique.COMBINED
                use_rag = True
            elif s == "combined":
                technique = PromptTechnique.COMBINED
                use_rag = False
            elif s == "one_shot_rag":
                technique = PromptTechnique.SECURITY_FOCUSED
                use_rag = True
            elif s == "one_shot":
                technique = PromptTechnique.SECURITY_FOCUSED
                use_rag = False

        # 0.6) Semgrep 룰 프롬프트 전략 해석 (기본: cot_rag)
        semgrep_prompt_strategy = "cot_rag"
        if isinstance(rule_strategy, str):
            rs = rule_strategy.strip().lower()
            if rs in ("oneshot", "one_shot"):
                semgrep_prompt_strategy = "one_shot_rag" if rs != "one_shot" else "one_shot_rag"
            elif rs in ("one_shot_rag",):
                semgrep_prompt_strategy = "one_shot_rag"
            elif rs in ("cot",):
                semgrep_prompt_strategy = "cot"
            elif rs in ("cot_rag",):
                semgrep_prompt_strategy = "cot_rag"
            elif rs in ("combined",):
                semgrep_prompt_strategy = "combined"
            elif rs in ("combined_rag",):
                semgrep_prompt_strategy = "combined_rag"

        # 1) 스캔 실행
        if log_verbose:
            logger.info("[pipeline] scan:start")
        # 새 전략: PatchService로 전체 코드 단위 수행
        t_scan = time.perf_counter()
        scan_response = await scanner_service.scan_code(request)
        timings["scan_seconds"] = round(time.perf_counter() - t_scan, 3)
        if log_verbose:
            logger.info(f"[pipeline] scan:end elapsed={timings['scan_seconds']}s")

        language = Language(request.language)
        if not scan_response:  # 방어적 체크
            raise HTTPException(status_code=500, detail="스캔 실패")

        t_patch = time.perf_counter()
        patch_service = PatchService(scanner_service)
        patch_result = await patch_service.run_patch(request=request)
        timings["patch_seconds"] = round(time.perf_counter() - t_patch, 3)

        # async def _fix_one(meta: Dict[str, Any], s: str) -> Tuple[str, str]:
        #     system_prompt = (
        #         "You are a world-class secure code engineer. For the given vulnerable code block, "
        #         "produce a secure, production-ready rewrite that removes ONLY the vulnerabilities listed (CWE list). "
        #         "Output only a single fenced code block labeled with the language.\n\n"
        #         "[SECURITY HARD RULES]\n"
        #         "- Never use shell invocation for command execution (no /bin/sh, cmd.exe, or single-string exec).\n"
        #         "- Use API-based execution with argument array (e.g., Java ProcessBuilder(\"cmd\", arg) or Python subprocess.run([...], shell=False)).\n"
        #         "- Do NOT concatenate user input into commands. No string + variable to build commands.\n"
        #         "- Enforce strict allowlist validation for all external inputs (regex or explicit set). Reject invalid inputs.\n"
        #         "- Disallow relative paths (./, ../). Use only allowlisted absolute commands/paths.\n"
        #         "- Principle of least privilege: do not escalate privileges; do not add dangerous flags.\n"
        #         "- Preserve original functionality while applying the fixes."
        #     )
        #     cwe_list = ", ".join(f"CWE-{c}" for c in meta.get("cwes", [])) or "N/A"
        #     user_prompt = (
        #         f"Language: {language.value}\n"
        #         f"Target Function: {meta.get('function_name','unknown')} (lines {meta.get('start')}..{meta.get('end')})\n"
        #         f"Vulnerabilities to fix (strict scope): {cwe_list}\n\n"
        #         f"```{language.value}\n{s}\n```"
        #     )
        #     async with sem:
        #         ans = await asyncio.to_thread(llm.ask, system_prompt, user_prompt)
        #     ans = ans or ""
        #     fixed = _extract_first_code_block(ans, language) or s
        #     return fixed, ans

        async def _fix_one(meta: Dict[str, Any], s: str) -> Tuple[str, str]:
            # 4.a) Hard security rules (항상 적용)
            hard_rules = (
                "[SECURITY HARD RULES]\n"
                "- Never use shell invocation for command execution (no /bin/sh, cmd.exe, or single-string exec).\n"
                "- Use API-based execution with argument array (e.g., Java ProcessBuilder(\"cmd\", arg) or Python subprocess.run([...], shell=False)).\n"
                "- Do NOT concatenate user input into commands. No string + variable to build commands.\n"
                "- Enforce strict allowlist validation for all external inputs (regex or explicit set). Reject invalid inputs.\n"
                "- Disallow relative paths (./, ../). Use only allowlisted absolute commands/paths.\n"
                "- Principle of least privilege: do not escalate privileges; do not add dangerous flags.\n"
                "- Preserve original functionality while applying the fixes.\n"
            )

            # 4.b) 그룹 내 취약점만 필터링하여 COMBINED 프롬프트 생성
            try:
                group_vulns: List[Any] = []
                s_line = int(meta.get("start", 1))
                e_line = int(meta.get("end", s_line))
                for v in (vulns or []):
                    try:
                        ls = int(getattr(v, "line_start", 0) or 0)
                        le = int(getattr(v, "line_end", ls) or ls)
                    except Exception:
                        ls, le = 0, 0
                    if ls >= s_line and le <= e_line:
                        group_vulns.append(v)

                base_prompt = scanner_service.generate_secure_code_prompt(
                    aggregated_vulnerabilities=group_vulns,
                    source_code=request.source_code,
                    language=language,
                    technique=technique,
                )
                system_prompt_base = base_prompt.system_prompt or ""
                user_prompt_base = base_prompt.user_prompt or ""
            except Exception:
                system_prompt_base = (
                    "You are a world-class secure code engineer. For the given vulnerable code block, "
                    "produce a secure, production-ready rewrite that removes ONLY the vulnerabilities listed (CWE list)."
                )
                user_prompt_base = ""

            # 4.c) 옵션: RAG(KISA/OWASP/코드 예제) 가이드 주입
            rag_section = ""
            if use_rag:
                try:
                    code_docs_all: List[Dict[str, Any]] = []
                    kisa_docs_all: List[Dict[str, Any]] = []
                    owasp_docs_all: List[Dict[str, Any]] = []
                    rag = RAGService(scanner_service)

                    for v in (group_vulns or []):
                        cwe_id = str(getattr(v, "cwe", "") or "").strip()
                        desc = getattr(v, "description", "") or ""
                        code_snippet = getattr(v, "code_snippet", "") or ""
                        if cwe_id:
                            code_docs_all += rag._retrieve_code_examples(
                                language=language.value,
                                cwe_id=cwe_id,
                                description=desc,
                                code_snippet=code_snippet,
                                top_k=1,
                            )
                            kisa_docs_all += rag._retrieve_text_guidelines(
                                query=(f"CWE-{cwe_id} {desc}".strip()),
                                db="kisa",
                                top_k=1,
                            )
                            owasp_docs_all += rag._retrieve_text_guidelines(
                                query=(desc or f"CWE-{cwe_id}"),
                                db="owasp",
                                top_k=1,
                            )

                    directive = (
                        "IMPORTANT: Strictly follow the retrieved security guidelines and secure code examples. "
                        "Priority: KISA > OWASP > Code Examples. Avoid unsafe dynamic execution and hard-coded secrets; "
                        "validate and allowlist external inputs; ensure compliance with OWASP/CWE best practices."
                    )
                    rag_section = "\n\n" + directive + "\n\n" + RAGService._format_rag_sections(
                        code_docs_all, kisa_docs_all, owasp_docs_all
                    )
                except Exception:
                    rag_section = ""

            # 4.d) 최종 프롬프트 구성
            system_prompt = f"{system_prompt_base}\n\n{hard_rules}" + (rag_section or "")
            cwe_list = ", ".join(f"CWE-{c}" for c in meta.get("cwes", [])) or "N/A"
            user_prompt = (
                    (user_prompt_base + "\n\n" if user_prompt_base else "") +
                    f"Language: {language.value}\n"
                    f"Target Function: {meta.get('function_name', 'unknown')} (lines {meta.get('start')}..{meta.get('end')})\n"
                    f"Vulnerabilities to fix (strict scope): {cwe_list}\n\n"
                    f"```{language.value}\n{s}\n```"
            )

            # 4.e) 호출 및 결과 추출
            async with sem:
                ans = await asyncio.to_thread(llm.ask, system_prompt, user_prompt)
            ans = ans or ""
            fixed = _extract_first_code_block(ans, language) or s
            return fixed, ans

        # Semgrep 룰 생성 단계는 제거되었으며, 대신 patch_result를 반환

        def _strip_yaml_fence(s: str) -> str:
            s = (s or "").strip()
            if s.startswith("```"):
                m = re.search(r"```(?:yaml)?\s*\n(.*?)```", s, re.DOTALL | re.IGNORECASE)
                if m:
                    return m.group(1).strip()
            return s

        def _merge_rule_yamls(texts: List[str]) -> str:
            # Prefer PyYAML merging when available
            if yaml is not None:
                merged_rules: List[Dict[str, Any]] = []
                for t in texts:
                    body = _strip_yaml_fence(t)
                    try:
                        data = yaml.safe_load(body) or {}
                    except Exception:
                        data = {}
                    if isinstance(data, dict) and "rules" in data and isinstance(data["rules"], list):
                        merged_rules.extend([r for r in data["rules"] if isinstance(r, dict)])
                    elif isinstance(data, dict) and ("id" in data or "pattern" in data):
                        merged_rules.append(data)
                    else:
                        # best-effort: ignore unparsable
                        pass
                # de-dup ids
                seen = set()
                deduped: List[Dict[str, Any]] = []
                for r in merged_rules:
                    rid = r.get("id")
                    key = rid if isinstance(rid, str) else None
                    if key is None or key not in seen:
                        if key:
                            seen.add(key)
                        deduped.append(r)
                try:
                    return yaml.safe_dump({"rules": deduped}, sort_keys=False, allow_unicode=True)
                except Exception:
                    pass
            # Fallback: naive textual merge
            items: List[str] = []
            for t in texts:
                body = _strip_yaml_fence(t)
                m = re.search(r"^\s*rules:\s*(.*)$", body, re.IGNORECASE | re.MULTILINE)
                if m:
                    idx = body.lower().find("rules:")
                    after = body[idx + len("rules:") :].strip()
                    items.append(after)
                else:
                    if body.strip().startswith("id:"):
                        indented = "\n".join([("  " + ln) for ln in body.splitlines()])
                        items.append("- " + indented.lstrip())
            normalized: List[str] = []
            for it in items:
                it_s = it.strip()
                if not it_s.startswith("- "):
                    lines = it_s.splitlines()
                    if lines:
                        lines[0] = "- " + lines[0].lstrip()
                    it_s = "\n".join(lines)
                normalized.append(it_s)
            return "rules:\n" + "\n".join(normalized)

        # 6) Save scan results JSON (keep behavior for visibility)
        try:
            base_dir = os.environ.get("SEMGREP_RULE_OUTPUT_DIR", "semgrep_rules")
            job_dir = os.path.join(base_dir, scan_response.job_id)
            os.makedirs(job_dir, exist_ok=True)
            def _vuln_to_dict(v: Any) -> Dict[str, Any]:
                return {
                    "file": getattr(v, "file", None) or getattr(v, "path", None) or getattr(v, "filename", None),
                    "line_start": getattr(v, "line_start", None),
                    "line_end": getattr(v, "line_end", None),
                    "severity": getattr(v, "severity", None),
                    "cwe": getattr(v, "cwe", None),
                    "scanner": getattr(v, "source", None) or getattr(v, "scanner", None),
                    "message": getattr(v, "message", None) or getattr(v, "title", None) or getattr(v, "rule_id", None),
                    "extra": getattr(v, "extra", None),
                }
            scan_json = {
                "job_id": scan_response.job_id,
                "language": language.value,
                "filename": request.filename,
                "options": getattr(request, "options", None).__dict__ if getattr(request, "options", None) else None,
                "vulnerabilities_processed": len(scan_response.aggregated_vulnerabilities or []),
                "groups_processed": None,
                "vulnerabilities": [
                    _vuln_to_dict(v) for v in (scan_response.aggregated_vulnerabilities or [])
                ],
                "timings": timings,
            }
            scan_path = os.path.join(job_dir, "scan_results.json")
            with open(scan_path, "w", encoding="utf-8") as f:
                json.dump(scan_json, f, ensure_ascii=False, indent=2)
        except Exception as e:
            scan_path = None
            if log_verbose:
                logger.info(f"[pipeline] save_scan_results:skip error={e}")

        total_elapsed = round(time.perf_counter() - t0, 3)
        if log_verbose:
            logger.info(f"[pipeline] total:end elapsed={total_elapsed}s")

        return {
            "job_id": scan_response.job_id,
            "language": language.value,
            "technique": technique.value,
            "rag_used": use_rag,
            "pipeline": "patch",
            "vulnerabilities_processed": len(scan_response.aggregated_vulnerabilities or []),
            "patched_code": patch_result.get("patched_code"),
            "unified_diff": patch_result.get("unified_diff"),
            "iterations": patch_result.get("iterations"),
            "passed": patch_result.get("passed"),
            "scan_result_path": scan_path,
            "timings": {
                **timings,
                "total_seconds": total_elapsed,
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"파이프라인 실행 실패: {e}")
