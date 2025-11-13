import asyncio
import difflib
from typing import Any, Dict, List, Optional, Tuple

from app.models.schemas import ScanRequest, Language, Severity
from app.services.scanning.scanner_service import ScannerService
from app.services.llm_service import LLMService

# Optional Java AST parser
try:
    import javalang  # type: ignore
except Exception:
    javalang = None  # fallback

# Optional patch applier
try:
    import whatthepatch  # type: ignore
except Exception:
    whatthepatch = None


class PatchService:
    """
    End-to-end patch pipeline:
      1) Initial scan to build context
      2) LLM secure code generation
      3) AST validation (python: ast.parse, java: javalang if available)
      4) Rescan loop with specific scanners per language until clean or max iterations
      5) Generate unified diff
      6) Apply patch to original using whatthepatch (if available) and return patched code
    """

    def __init__(self, scanner_service: Optional[ScannerService] = None, llm: Optional[LLMService] = None):
        self.scanner = scanner_service or ScannerService()
        self.llm = llm or LLMService()

    # ------------------------ Public API ------------------------
    async def run_patch(
        self,
        request: ScanRequest,
        max_iterations: int = 3,
        min_severity: Severity | str = Severity.LOW,
        use_rag: bool = False,
    ) -> Dict[str, Any]:
        language = Language(request.language)
        original_code = request.source_code

        # 1) Initial scan to prepare prompt context
        initial_scan = await self.scanner.scan_code(request)

        # 2) Ask LLM for secure code (combined prompt)
        prompt = self.scanner.generate_secure_code_prompt(
            aggregated_vulnerabilities=initial_scan.aggregated_vulnerabilities,
            source_code=original_code,
            language=language,
        )
        first_answer = await self.llm.ask_async(prompt.system_prompt, prompt.user_prompt)
        fixed_code = self._extract_first_code_block(first_answer or "", language) or original_code

        iterations: List[Dict[str, Any]] = []

        # 3) Validate AST and rescan loop
        for it in range(1, max_iterations + 1):
            syntax_ok, syntax_err = self._validate_syntax(fixed_code, language)
            iter_rec: Dict[str, Any] = {
                "iteration": it,
                "syntax_valid": syntax_ok,
                "syntax_error": syntax_err,
            }
            if not syntax_ok:
                # Provide syntax error feedback to LLM and retry
                feedback_system, feedback_user = self._build_feedback_prompts(
                    base_system=prompt.system_prompt,
                    base_user=prompt.user_prompt,
                    language=language,
                    feedback=f"SyntaxError: {syntax_err}\nPlease output corrected full code only.",
                    latest_code=fixed_code,
                )
                answer = await self.llm.ask_async(feedback_system, feedback_user)
                fixed_code = self._extract_first_code_block(answer or "", language) or fixed_code
                iter_rec["rescan_total_issues"] = None
                iter_rec["rescan_severity_summary"] = None
                iterations.append(iter_rec)
                continue

            # 4) Rescan with specific scanners per language
            specific_scanners = ["bandit", "semgrep"] if language == Language.PYTHON else ["horusec", "semgrep"]
            rescan_req = ScanRequest(
                language=language,
                source_code=fixed_code,
                filename=request.filename,
                options={
                    "enable_cpg_analysis": False,
                    "specific_scanners": specific_scanners,
                    "min_severity": min_severity,
                    "timeout": request.options.timeout if getattr(request, "options", None) else 300,
                },
            )
            # Pydantic model expects ScanOptions; reconstruct via dict is allowed in BaseModel
            rescan = await self.scanner.scan_code(rescan_req)
            iter_rec["rescan_total_issues"] = rescan.total_vulnerabilities
            iter_rec["rescan_severity_summary"] = rescan.severity_summary

            iterations.append(iter_rec)

            if rescan.total_vulnerabilities == 0:
                break

            # 5) Build vulnerability-aware prompt for next iteration
            feedback_system, feedback_user = self._build_feedback_prompts(
                base_system=prompt.system_prompt,
                base_user=prompt.user_prompt,
                language=language,
                feedback=self._format_vuln_feedback(rescan.aggregated_vulnerabilities),
                latest_code=fixed_code,
            )
            answer = await self.llm.ask_async(feedback_system, feedback_user)
            new_code = self._extract_first_code_block(answer or "", language) or fixed_code
            fixed_code = new_code

        # 6) Compute unified diff and apply patch via whatthepatch (if available)
        unified_diff = self._unified_diff(original_code, fixed_code, request.filename)
        patched_via_patch = self._apply_patch_with_whatthepatch(original_code, unified_diff) or fixed_code

        return {
            "job_id": initial_scan.job_id,
            "language": language.value,
            "iterations": iterations,
            "passed": (iterations and iterations[-1].get("rescan_total_issues") == 0) or (len(iterations) == 0),
            "unified_diff": unified_diff,
            "patched_code": patched_via_patch,
        }

    # ------------------------ Helpers ------------------------
    @staticmethod
    def _extract_first_code_block(text: str, language: Language) -> Optional[str]:
        if not text:
            return None
        lang = language.value
        import re
        pattern_lang = re.compile(rf"```\s*{re.escape(lang)}\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
        m = pattern_lang.search(text)
        if m:
            return m.group(1).strip()
        pattern_any = re.compile(r"```\s*\n(.*?)```", re.DOTALL)
        m2 = pattern_any.search(text)
        if m2:
            return m2.group(1).strip()
        return None

    # Deprecated: synchronous ask kept for compatibility via LLMService

    @staticmethod
    def _validate_syntax(code: str, language: Language) -> Tuple[bool, Optional[str]]:
        try:
            if language == Language.PYTHON:
                import ast
                ast.parse(code)
                return True, None
            else:
                if javalang is not None:
                    try:
                        list(javalang.tokenizer.Lexer(code))  # tokenize
                        javalang.parse.parse(code)  # may raise
                        return True, None
                    except Exception as e:
                        return False, str(e)
                # Fallback: basic braces balance check
                opens = code.count("{")
                closes = code.count("}")
                return (opens == closes), (None if opens == closes else "Mismatched braces")
        except Exception as e:  # pragma: no cover
            return False, str(e)

    @staticmethod
    def _unified_diff(original: str, fixed: str, filename: Optional[str]) -> str:
        a = original.splitlines(keepends=False)
        b = fixed.splitlines(keepends=False)
        diff = difflib.unified_diff(
            a,
            b,
            fromfile=f"a/{filename or 'original'}",
            tofile=f"b/{filename or 'fixed'}",
            lineterm="",
        )
        return "\n".join(list(diff))

    @staticmethod
    def _format_vuln_feedback(vulns: List[Any]) -> str:
        lines: List[str] = [
            "Please rework the code. The following vulnerabilities were still detected after your fix:",
        ]
        for v in (vulns or []):
            try:
                cwe = getattr(v, "cwe", None) or 0
                sev = getattr(v, "severity", None)
                sev_val = getattr(sev, "value", str(sev)) if sev is not None else "unknown"
                desc = getattr(v, "description", "")
                loc = f"{getattr(v, 'file_path', '')}:{getattr(v, 'line_start', 0)}-{getattr(v, 'line_end', 0)}"
                lines.append(f"- CWE-{cwe} [{sev_val}] at {loc}: {desc}")
            except Exception:
                continue
        lines.append("Output the full corrected code only in a fenced code block.")
        return "\n".join(lines)

    @staticmethod
    def _build_feedback_prompts(
        base_system: str,
        base_user: str,
        language: Language,
        feedback: str,
        latest_code: str,
    ) -> Tuple[str, str]:
        hard_rules = (
            "[SECURITY HARD RULES]\n"
            "- Never use shell invocation for command execution (no /bin/sh, cmd.exe, or single-string exec).\n"
            "- Use API-based execution with argument array.\n"
            "- Do NOT concatenate user input into commands.\n"
            "- Validate and allowlist external inputs.\n"
            "- Disallow relative paths; use only allowlisted absolute paths.\n"
            "- Principle of least privilege; preserve functionality.\n"
        )
        system_prompt = f"{base_system}\n\n{hard_rules}\n\n[FEEDBACK]\n{feedback}"
        user_prompt = (
            f"Language: {language.value}\n\n"
            f"Latest code to revise:\n```{language.value}\n{latest_code}\n```\n"
            f"Please return only the full corrected code in a fenced block."
        )
        return system_prompt, user_prompt

    @staticmethod
    def _apply_patch_with_whatthepatch(original: str, unified_diff: str) -> Optional[str]:
        if not whatthepatch:
            return None
        try:
            patches = list(whatthepatch.parse_patch(unified_diff))
            # whatthepatch works per file; here we expect single-file patch
            if not patches:
                return None
            # Apply patch to original lines
            original_lines = original.splitlines(keepends=True)
            for p in patches:
                # Build new content
                new_lines: List[str] = []
                idx = 0
                for h in p.hunks:
                    # Copy unchanged lines up to this hunk
                    while idx < (h.target_start - 1) and idx < len(original_lines):
                        new_lines.append(original_lines[idx])
                        idx += 1
                    # Apply hunk changes
                    for change in h:
                        if change.is_added:
                            new_lines.append((change.line or "") + "\n")
                        elif change.is_removed:
                            idx += 1  # skip a line from original
                        else:  # context
                            if idx < len(original_lines):
                                new_lines.append(original_lines[idx])
                                idx += 1
                # Append remaining lines
                while idx < len(original_lines):
                    new_lines.append(original_lines[idx])
                    idx += 1
                return "".join(new_lines)
        except Exception:
            return None
