import asyncio
import difflib
import logging
from typing import Any, Dict, List, Optional, Tuple

from app.models.schemas import ScanRequest, Language, Severity
from app.services.llm_service import LLMService
from app.services.pipeline_prompt_strategies import build_combined_with_rag
from app.services.scanning.scanner_service import ScannerService
from app.utils.code_slicing import slice_function_with_header, find_enclosing_symbol

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
        """
        여러 취약점 그룹에 대한 역순 병합 방식의 엔드투엔드 패치 파이프라인

        기존 구현 대비 변경사항:
        - 그룹들을 끝 라인 기준 역순으로 병합하여 라인 오프셋 문제 해결
        - 정확한 라인 번호 조정을 위한 오프셋 추적 추가
        - 병합 프로세스 디버깅을 위한 로깅 강화
        """
        language = Language(request.language)
        original_code = request.source_code

        # 1) 프롬프트 컨텍스트 준비를 위한 초기 스캔
        self.logger.info("[Patch] 초기 스캔 시작")
        initial_scan = await self.scanner.scan_code(request)
        self.logger.info(
            "[Patch] 초기 스캔 완료: 총 취약점=%s 에러=%s",
            initial_scan.total_vulnerabilities,
            len(initial_scan.scanner_errors or [])
        )

        # 2) 프롬프트 빌드 (슬라이싱 활성화 시)
        opts = getattr(request, "options", None)
        use_slice = bool(getattr(opts, "use_code_slicing", False))
        parallel_fix = bool(getattr(opts, "parallel_slice_fix", False))

        if use_slice and initial_scan.aggregated_vulnerabilities:
            # 앵커: 첫 번째 취약점
            first_v = initial_scan.aggregated_vulnerabilities[0]
            target_line = int(getattr(first_v, "line_start", 1) or 1)

            # 헤더 컨텍스트를 포함한 함수/메서드 슬라이싱
            try:
                code_slice = slice_function_with_header(language, original_code, target_line)
            except Exception:
                # 폴백: 작은 윈도우 범위
                lines = original_code.splitlines()
                i = max(0, target_line - 1)
                start = max(0, i - 30)
                end = min(len(lines), i + 30)
                code_slice = "\n".join(lines[start:end])

            # 포함 심볼 결정 및 범위 내 취약점 그룹화
            func_nm, s_line, e_line = ("unknown", max(1, target_line - 1), target_line + 1)
            sym = find_enclosing_symbol(language, original_code, target_line)
            if sym:
                func_nm, s_line, e_line = sym

            # 병렬 슬라이스 수정이 활성화된 경우 포함 심볼별로 취약점 그룹화
            if parallel_fix:
                self.logger.info("[Patch] 병렬 슬라이스 수정 활성화")
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

                # 그룹화 실패 시 단일 그룹으로 폴백
                if len(groups) <= 1:
                    parallel_fix = False
                    self.logger.info("[Patch] 병렬 처리를 위한 그룹이 부족함; 단일 슬라이스로 폴백")
                else:
                    # 그룹별 프롬프트 빌드 및 병렬 LLM 호출
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

                        meta_g = {
                            "function_name": fnm,
                            "start": gs,
                            "end": ge,
                            "cwes": [
                                getattr(v, "cwe", None)
                                for v in vulns
                                if getattr(v, "cwe", None) is not None
                            ]
                        }

                        if use_rag:
                            sys_g, usr_g = build_combined_with_rag(
                                self.scanner, original_code, language, vulns, meta_g, gslice
                            )
                        else:
                            sys_g, usr_g = self._compose_slice_prompts_without_rag(
                                original_code, language, vulns, meta_g, gslice
                            )

                        prompts.append(((fnm, gs, ge), (sys_g, usr_g)))

                    self.logger.info("[Patch] %d개 병렬 LLM 호출 전송", len(prompts))
                    tasks = [self.llm.ask_async(sys, usr) for _, (sys, usr) in prompts]
                    answers = await asyncio.gather(*tasks, return_exceptions=True)

                    # ✅ 개선: 끝 라인 기준 역순으로 그룹 정렬
                    # 순차 병합 중 라인 오프셋 문제 방지
                    indexed_prompts = [
                        (prompts[i][0], i) for i in range(len(prompts))
                    ]
                    # 끝 라인(ge) 기준 내림차순 정렬
                    indexed_prompts.sort(key=lambda x: x[0][2], reverse=True)

                    self.logger.info(
                        "[Patch] %d개 그룹을 역순으로 병합: %s",
                        len(indexed_prompts),
                        [(fnm, gs, ge) for (fnm, gs, ge), _ in indexed_prompts]
                    )

                    merged_code_lines = original_code.splitlines()

                    for (fnm, gs, ge), idx in indexed_prompts:
                        ans = answers[idx]
                        if isinstance(ans, Exception) or not ans:
                            self.logger.warning(
                                "[Patch] 그룹 %s (%d-%d)에 대한 LLM 응답 누락; 건너뜀",
                                fnm, gs, ge
                            )
                            continue

                        fixed_slice = self._extract_first_code_block(str(ans), language)
                        if not fixed_slice:
                            self.logger.warning(
                                "[Patch] %s:%d-%d에 대한 LLM 응답에 코드 블록 없음; 건너뜀",
                                fnm, gs, ge
                            )
                            continue

                        # 함수 본문 범위를 반환된 코드로 교체
                        # 라인 번호는 1-based 포함형
                        start_i = max(0, gs - 1)
                        end_i = max(start_i, ge - 1)
                        new_lines = fixed_slice.splitlines()

                        original_line_count = end_i - start_i
                        new_line_count = len(new_lines)

                        self.logger.debug(
                            "[Patch] %s (%d-%d) 병합: %d줄 -> %d줄 (차이: %+d)",
                            fnm, gs, ge, original_line_count, new_line_count,
                            new_line_count - original_line_count
                        )

                        # 슬라이스 교체
                        merged_code_lines[start_i:end_i] = new_lines

                    aggregated_code = "\n".join(merged_code_lines)

                    # 이제 aggregated_code를 첫 번째 fixed_code로 처리
                    prompt = type("P", (), {
                        "system_prompt": "[parallel_slice_fix]",
                        "user_prompt": ""
                    })
                    fixed_code = aggregated_code
                    self.logger.info("[Patch] 병렬 슬라이스 병합 완료")

            if not parallel_fix:
                # 단일 슬라이스 모드
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
                    "cwes": [
                        getattr(v, "cwe", None)
                        for v in group_vulns
                        if getattr(v, "cwe", None) is not None
                    ],
                }

                if use_rag:
                    sys_prompt, usr_prompt = build_combined_with_rag(
                        scanner_service=self.scanner,
                        request_source=original_code,
                        language=language,
                        group_vulns=group_vulns,
                        meta=meta,
                        code_slice=code_slice,
                    )
                else:
                    sys_prompt, usr_prompt = self._compose_slice_prompts_without_rag(
                        original_code, language, group_vulns, meta, code_slice
                    )

                self.logger.info("[Patch] 단일 슬라이스 수정을 위한 LLM 호출")
                first_answer = await self.llm.ask_async(sys_prompt, usr_prompt)
                prompt = type("P", (), {
                    "system_prompt": sys_prompt,
                    "user_prompt": usr_prompt
                })
                fixed_code = self._extract_first_code_block(first_answer or "", language) or original_code

        else:
            # 폴백: 전체 파일 통합 프롬프트
            prompt = self.scanner.generate_secure_code_prompt(
                aggregated_vulnerabilities=initial_scan.aggregated_vulnerabilities,
                source_code=original_code,
                language=language,
            )
            self.logger.info("[Patch] 전체 파일 수정을 위한 LLM 호출")
            first_answer = await self.llm.ask_async(prompt.system_prompt, prompt.user_prompt)
            fixed_code = self._extract_first_code_block(first_answer or "", language) or original_code

        iterations: List[Dict[str, Any]] = []

        # 3) AST 검증 및 재스캔 루프
        for it in range(1, max_iterations + 1):
            self.logger.info("[Patch] 반복 %d: 구문 검증 중", it)
            syntax_ok, syntax_err = self._validate_syntax(fixed_code, language)

            iter_rec: Dict[str, Any] = {
                "iteration": it,
                "syntax_valid": syntax_ok,
                "syntax_error": syntax_err,
            }

            if not syntax_ok:
                # LLM에 구문 오류 피드백 제공 및 재시도
                self.logger.warning("[Patch] 구문 오류: %s", syntax_err)
                feedback_system, feedback_user = self._build_feedback_prompts(
                    base_system=prompt.system_prompt,
                    base_user=prompt.user_prompt,
                    language=language,
                    feedback=f"구문 오류: {syntax_err}\n수정된 전체 코드만 출력해주세요.",
                    latest_code=fixed_code,
                )
                answer = await self.llm.ask_async(feedback_system, feedback_user)
                fixed_code = self._extract_first_code_block(answer or "", language) or fixed_code
                iter_rec["rescan_total_issues"] = None
                iter_rec["rescan_severity_summary"] = None
                iterations.append(iter_rec)
                continue

            # 4) 언어별 특정 스캐너로 재스캔
            specific_scanners = (
                ["bandit", "semgrep"] if language == Language.PYTHON else ["horusec", "semgrep"]
            )

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

            self.logger.info("[Patch] 반복 %d: %s로 재스캔 중", it, ",".join(specific_scanners))
            rescan = await self.scanner.scan_code(rescan_req)
            iter_rec["rescan_total_issues"] = rescan.total_vulnerabilities
            iter_rec["rescan_severity_summary"] = rescan.severity_summary
            iterations.append(iter_rec)

            if rescan.total_vulnerabilities == 0:
                self.logger.info("[Patch] 반복 %d: 클린, 루프 중단", it)
                break
            else:
                # 재스캔 실패 시 상세 취약점 로깅
                self.logger.warning(
                    "[Patch] 반복 %d: 재스캔 실패 - %d개 이슈 발견",
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
                            "[Patch] - CWE-%s [%s] at %s: %s",
                            cwe,
                            sev_val,
                            loc,
                            (desc[:300] + "...") if isinstance(desc, str) and len(desc) > 300 else desc,
                        )
                    except Exception:
                        continue

                # 5) 다음 반복을 위한 취약점 인식 프롬프트 빌드
                feedback_system, feedback_user = self._build_feedback_prompts(
                    base_system=prompt.system_prompt,
                    base_user=prompt.user_prompt,
                    language=language,
                    feedback=self._format_vuln_feedback(rescan.aggregated_vulnerabilities, fixed_code),
                    latest_code=fixed_code,
                    iteration=it,
                )

                self.logger.info("[Patch] 반복 %d: 다음 수정을 위한 LLM 호출", it)
                answer = await self.llm.ask_async(feedback_system, feedback_user)
                new_code = self._extract_first_code_block(answer or "", language) or fixed_code
                fixed_code = new_code

        # 6) unified diff 계산 및 whatthepatch로 패치 적용 (가능한 경우)
        self.logger.info("[Patch] unified diff 계산 및 패치 적용 중")
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
    def _format_vuln_feedback(vulns: List[Any], code: str = "") -> str:
        lines: List[str] = [
            "The following vulnerabilities were still detected after your fix:",
            ""
        ]

        code_lines = code.splitlines() if code else []

        for idx, v in enumerate(vulns or [], 1):
            try:
                cwe = getattr(v, "cwe", None) or 0
                sev = getattr(v, "severity", None)
                sev_val = getattr(sev, "value", str(sev)) if sev is not None else "unknown"
                line_start = int(getattr(v, "line_start", 0))
                line_end = int(getattr(v, "line_end", line_start))

                lines.append(f"### Issue {idx}: CWE-{cwe} [{sev_val}]")
                lines.append(f"**Location**: Lines {line_start}-{line_end}")

                # 실제 코드 라인 표시 (앞뒤 3줄 컨텍스트)
                if code_lines and 0 < line_start <= len(code_lines):
                    lines.append("**Code:**")
                    lines.append("```")

                    start = max(0, line_start - 4)
                    end = min(len(code_lines), line_end + 3)

                    for i in range(start, end):
                        if i < len(code_lines):
                            is_problem = (line_start - 1) <= i < line_end
                            prefix = ">>> " if is_problem else "    "
                            lines.append(f"{prefix}{i + 1}: {code_lines[i]}")

                    lines.append("```")
            except Exception:
                continue

        lines.append("**Instructions:**")
        lines.append("- Review each vulnerability carefully")
        lines.append("- Apply the necessary security fixes")
        lines.append("- Output the COMPLETE corrected code in a fenced code block")

        return "\n".join(lines)

    @staticmethod
    def _build_feedback_prompts(
        base_system: str,
        base_user: str,
        language: Language,
        feedback: str,
        latest_code: str,
        iteration: int = 1,
    ) -> Tuple[str, str]:
        # 1. Role
        role = f"You are a security engineer specializing in {language.value} secure coding."

        # 2. Iteration 컨텍스트
        urgency = ""
        if iteration == 2:
            urgency = "\n[WARNING] First fix failed. Apply MORE defensive patterns.\n"
        elif iteration >= 3:
            urgency = "\n[CRITICAL] Last attempt! Use the MOST secure approach.\n"

        hard_rules = (
            "[SECURITY HARD RULES]\n"
            "- Never use shell invocation for command execution (no /bin/sh, cmd.exe, or single-string exec).\n"
            "- Use API-based execution with argument array.\n"
            "- Do NOT concatenate user input into commands.\n"
            "- Validate and allowlist external inputs.\n"
            "- Disallow relative paths; use only allowlisted absolute paths.\n"
            "- Principle of least privilege; preserve functionality.\n"
        )

        output_rule = """
        [OUTPUT]
        Provide ONLY complete, syntactically valid code in a code fence. No explanations.
        """

        system_prompt = f"{role}{urgency}\n{base_system}\n{hard_rules}\n{output_rule}\nFEEDBACK:\n{feedback}"
        user_prompt = (
            f"Language: {language.value}\n\n"
            f"Latest code to revise:\n```{language.value}\n{latest_code}\n```\n"
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
