import asyncio
import difflib
import logging
from typing import Any, Dict, List, Optional, Tuple

from app.models.schemas import ScanRequest, Language, Severity
from app.services.scanning.scanner_service import ScannerService
from app.services.llm_service import LLMService
from app.utils.code_slicing import slice_function_with_header, find_enclosing_symbol
from app.services.pipeline_prompt_strategies import build_combined_with_rag

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
        self.logger = logging.getLogger(__name__)

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
        self.logger.info("[Patch] Initial scan started")
        initial_scan = await self.scanner.scan_code(request)
        self.logger.info("[Patch] Initial scan done: total_vulns=%s errors=%s", initial_scan.total_vulnerabilities, len(initial_scan.scanner_errors or []))

        # 2) Build prompts (slicing-aware if enabled)
        opts = getattr(request, "options", None)
        use_slice = bool(getattr(opts, "use_code_slicing", False))
        parallel_fix = bool(getattr(opts, "parallel_slice_fix", False))
        if use_slice and initial_scan.aggregated_vulnerabilities:
            # Anchor: first vulnerability
            first_v = initial_scan.aggregated_vulnerabilities[0]
            target_line = int(getattr(first_v, "line_start", 1) or 1)
            # Slice function/method with header context
            try:
                code_slice = slice_function_with_header(language, original_code, target_line)
            except Exception:
                # Fallback small window
                lines = original_code.splitlines()
                i = max(0, target_line - 1)
                start = max(0, i - 30)
                end = min(len(lines), i + 30)
                code_slice = "\n".join(lines[start:end])

            # Determine enclosing symbol and group vulns within the range
            func_nm, s_line, e_line = ("unknown", max(1, target_line - 1), target_line + 1)
            sym = find_enclosing_symbol(language, original_code, target_line)
            if sym:
                func_nm, s_line, e_line = sym
            # Group vulnerabilities by enclosing symbol if parallel slice fix is enabled
            if parallel_fix:
                self.logger.info("[Patch] Parallel slice fix enabled")
                groups: Dict[Tuple[str, int, int], List[Any]] = {}
                for v in initial_scan.aggregated_vulnerabilities:
                    ls = int(getattr(v, "line_start", 0) or 0)
                    if ls <= 0:
                        continue
                    s = find_enclosing_symbol(language, original_code, ls) or None
                    if not s:
                        continue
                    key = (s[0], s[1], s[2])
                    groups.setdefault(key, []).append(v)
                # Fallback to single group if grouping failed
                if len(groups) <= 1:
                    parallel_fix = False
                    self.logger.info("[Patch] Not enough groups for parallel; fallback to single-slice")
                else:
                    # Build prompts per group and ask LLM in parallel
                    prompts: List[Tuple[Tuple[str, int, int], Tuple[str, str]]] = []
                    for (fnm, gs, ge), vulns in groups.items():
                        tline = int(getattr(vulns[0], "line_start", gs) or gs)
                        try:
                            gslice = slice_function_with_header(language, original_code, tline)
                        except Exception:
                            lines = original_code.splitlines()
                            i = max(0, tline - 1)
                            start = max(0, i - 30)
                            end = min(len(lines), i + 30)
                            gslice = "\n".join(lines[start:end])
                        meta_g = {"function_name": fnm, "start": gs, "end": ge, "cwes": [getattr(v, "cwe", None) for v in vulns if getattr(v, "cwe", None) is not None]}
                        sys_g, usr_g = build_combined_with_rag(self.scanner, original_code, language, vulns, meta_g, gslice) if use_rag else self._compose_slice_prompts_without_rag(original_code, language, vulns, meta_g, gslice)
                        prompts.append(((fnm, gs, ge), (sys_g, usr_g)))

                    self.logger.info("[Patch] Dispatching %d parallel LLM calls", len(prompts))
                    tasks = [self.llm.ask_async(sys, usr) for _, (sys, usr) in prompts]
                    answers = await asyncio.gather(*tasks, return_exceptions=True)

                    # Sequentially merge each slice's fixed code into the original
                    merged_code_lines = original_code.splitlines()
                    for idx, ans in enumerate(answers):
                        if isinstance(ans, Exception) or not ans:
                            self.logger.warning("[Patch] LLM answer missing for group #%d; skipping", idx)
                            continue
                        fnm, gs, ge = prompts[idx][0]
                        fixed_slice = self._extract_first_code_block(str(ans), language)
                        if not fixed_slice:
                            self.logger.warning("[Patch] No code block in LLM answer for %s:%d-%d; skipping", fnm, gs, ge)
                            continue
                        # Replace function body range with returned code
                        # Lines are 1-based inclusive
                        start_i = max(0, gs - 1)
                        end_i = max(start_i, ge - 1)
                        new_lines = fixed_slice.splitlines()
                        merged_code_lines[start_i:end_i] = new_lines  # simple splice
                    aggregated_code = "\n".join(merged_code_lines)

                    # Now treat aggregated_code as first fixed_code
                    prompt = type("P", (), {"system_prompt": "[parallel_slice_fix]", "user_prompt": ""})
                    fixed_code = aggregated_code
                    self.logger.info("[Patch] Parallel slice merge complete")
                
            if not parallel_fix:
                group_vulns = []
                for v in initial_scan.aggregated_vulnerabilities:
                    ls = int(getattr(v, "line_start", 0) or 0)
                    le = int(getattr(v, "line_end", ls) or ls)
                    if s_line <= ls and le <= e_line:
                        group_vulns.append(v)
                if not group_vulns:
                    group_vulns = [first_v]

                meta = {
                    "function_name": func_nm,
                    "start": s_line,
                    "end": e_line,
                    "cwes": [getattr(v, "cwe", None) for v in group_vulns if getattr(v, "cwe", None) is not None],
                }
                sys_prompt, usr_prompt = build_combined_with_rag(
                    scanner_service=self.scanner,
                    request_source=original_code,
                    language=language,
                    group_vulns=group_vulns,
                    meta=meta,
                    code_slice=code_slice,
                ) if use_rag else self._compose_slice_prompts_without_rag(original_code, language, group_vulns, meta, code_slice)
                self.logger.info("[Patch] Asking LLM for single-slice fix")
                first_answer = await self.llm.ask_async(sys_prompt, usr_prompt)
                prompt = type("P", (), {"system_prompt": sys_prompt, "user_prompt": usr_prompt})  # minimal holder
        else:
            # Fallback: whole-file combined prompt
            prompt = self.scanner.generate_secure_code_prompt(
                aggregated_vulnerabilities=initial_scan.aggregated_vulnerabilities,
                source_code=original_code,
                language=language,
            )
            self.logger.info("[Patch] Asking LLM for whole-file fix")
            first_answer = await self.llm.ask_async(prompt.system_prompt, prompt.user_prompt)
        if not parallel_fix:
            fixed_code = self._extract_first_code_block(first_answer or "", language) or original_code

        iterations: List[Dict[str, Any]] = []

        # 3) Validate AST and rescan loop
        for it in range(1, max_iterations + 1):
            self.logger.info("[Patch] Iteration %d: validating syntax", it)
            syntax_ok, syntax_err = self._validate_syntax(fixed_code, language)
            iter_rec: Dict[str, Any] = {
                "iteration": it,
                "syntax_valid": syntax_ok,
                "syntax_error": syntax_err,
            }
            if not syntax_ok:
                # Provide syntax error feedback to LLM and retry
                self.logger.warning("[Patch] Syntax invalid: %s", syntax_err)
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
            self.logger.info("[Patch] Iteration %d: rescanning with %s", it, ",".join(specific_scanners))
            rescan = await self.scanner.scan_code(rescan_req)
            iter_rec["rescan_total_issues"] = rescan.total_vulnerabilities
            iter_rec["rescan_severity_summary"] = rescan.severity_summary

            iterations.append(iter_rec)

            if rescan.total_vulnerabilities == 0:
                self.logger.info("[Patch] Iteration %d: clean, stopping loop", it)
                break
            else:
                # Log detailed vulnerabilities when rescan fails
                self.logger.warning(
                    "[Patch] Iteration %d: rescan failed with %d issue(s)",
                    it,
                    rescan.total_vulnerabilities,
                )
                for v in getattr(rescan, "aggregated_vulnerabilities", []) or []:
                    try:
                        cwe = getattr(v, "cwe", None) or 0
                        sev = getattr(v, "severity", None)
                        sev_val = getattr(sev, "value", str(sev)) if sev is not None else "unknown"
                        desc = getattr(v, "description", "")
                        loc = f"{getattr(v, 'file_path', '')}:{getattr(v, 'line_start', 0)}-{getattr(v, 'line_end', 0)}"
                        self.logger.warning(
                            "[Patch]  - CWE-%s [%s] at %s: %s",
                            cwe,
                            sev_val,
                            loc,
                            (desc[:300] + "...") if isinstance(desc, str) and len(desc) > 300 else desc,
                        )
                    except Exception:
                        continue

            # 5) Build vulnerability-aware prompt for next iteration
            feedback_system, feedback_user = self._build_feedback_prompts(
                base_system=prompt.system_prompt,
                base_user=prompt.user_prompt,
                language=language,
                feedback=self._format_vuln_feedback(rescan.aggregated_vulnerabilities),
                latest_code=fixed_code,
            )
            self.logger.info("[Patch] Iteration %d: asking LLM for next fix", it)
            answer = await self.llm.ask_async(feedback_system, feedback_user)
            new_code = self._extract_first_code_block(answer or "", language) or fixed_code
            fixed_code = new_code

        # 6) Compute unified diff and apply patch via whatthepatch (if available)
        self.logger.info("[Patch] Computing unified diff and applying patch")
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
                        # Tokenize and parse using javalang
                        list(javalang.tokenizer.tokenize(code))
                        javalang.parse.parse(code)
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
    def _compose_slice_prompts_without_rag(
        request_source: str,
        language: Language,
        group_vulns: List[Any],
        meta: Dict[str, Any],
        code_slice: str,
    ) -> Tuple[str, str]:
        # Mirror of build_combined_with_rag but without retrieval augmentation
        hard_rules = (
            "[SECURITY HARD RULES]\n"
            "- Never use shell invocation for command execution (no /bin/sh, cmd.exe, or single-string exec).\n"
            "- Use API-based execution with argument array.\n"
            "- Do NOT concatenate user input into commands.\n"
            "- Validate and allowlist external inputs.\n"
            "- Disallow relative paths; use only allowlisted absolute paths.\n"
            "- Principle of least privilege; preserve functionality.\n"
        )
        system_prompt = hard_rules
        cwe_list = ", ".join(f"CWE-{getattr(v, 'cwe', 'N/A')}" for v in (group_vulns or [])) or "N/A"
        user_prompt = (
            f"Language: {language.value}\n"
            f"Target Function: {meta.get('function_name','unknown')} (lines {meta.get('start')}..{meta.get('end')})\n"
            f"Vulnerabilities to fix (strict scope): {cwe_list}\n\n"
            f"```{language.value}\n{code_slice}\n```"
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
