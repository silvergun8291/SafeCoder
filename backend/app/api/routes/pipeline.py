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
from app.services.semgrep_rule_service import SemgrepRuleService
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
    summary="스캔 → 슬라이싱(모든 취약점) → LLM 시큐어코딩(블록별) → 단일 Semgrep Autofix Rule",
    description=(
        "소스 코드를 스캔하고, 탐지된 모든 취약점에 대해 해당 코드 블록을 파서 기반으로 슬라이싱합니다. "
        "각 블록별로 LLM 시큐어 코딩을 수행한 뒤, 모든 변경을 종합하여 하나의 Semgrep Autofix Rule을 생성합니다."
    ),
)
async def scan_llm_autofix_rule(
    request: ScanRequest,
    technique: PromptTechnique = PromptTechnique.COMBINED,
    use_rag: bool = True,
    # strategy 약어: combined|combined_rag|one_shot|one_shot_rag (제공 시 technique/use_rag를 덮어씀)
    strategy: Optional[str] = None,
    # semgrep rule 생성용 프롬프트 전략 약어: combined_rag|combined|cot_rag|cot|one_shot_rag|one_shot
    rule_strategy: Optional[str] = None,
    mode: str = "per_function",  # per_function | combined
    rule_mode: str = "single",  # single | per_cwe
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
        scan_response = await scanner_service.scan_code(request)
        timings["scan_seconds"] = round(time.perf_counter() - t0, 3)
        if log_verbose:
            logger.info(f"[pipeline] scan:end elapsed={timings['scan_seconds']}s")

        language = Language(request.language)
        if not scan_response.aggregated_vulnerabilities:
            raise HTTPException(status_code=400, detail="스캔 결과에 취약점이 없습니다.")
        vulns = scan_response.aggregated_vulnerabilities

        # 2) 그룹핑: 함수 단위로 취약점 묶기 (per_function 모드)
        t1 = time.perf_counter()
        if log_verbose:
            logger.info("[pipeline] grouping:start mode=%s", mode)
        group_map: DefaultDict[Tuple[str, int, int], Dict[str, Any]] = defaultdict(lambda: {"vulns": []})
        if mode == "per_function":
            for v in vulns:
                tl = int(v.line_start or 1)
                sym = find_enclosing_symbol(language, request.source_code, tl)
                if not sym:
                    # 파서 실패 시 해당 라인 기준 근사 그룹 키
                    key = (request.filename or "unknown", max(1, tl - 1), tl + 1)
                    group_map[key]["name"] = "unknown"
                    group_map[key]["start"] = max(1, tl - 1)
                    group_map[key]["end"] = tl + 1
                else:
                    name, s_line, e_line = sym
                    key = (request.filename or "unknown", s_line, e_line)
                    group_map[key]["name"] = name
                    group_map[key]["start"] = s_line
                    group_map[key]["end"] = e_line
                group_map[key]["vulns"].append(v)
        else:
            # combined 모드: 단일 그룹으로 취급
            if vulns:
                key = (request.filename or "unknown", 1, max(1, len(request.source_code.splitlines())))
                group_map[key] = {
                    "name": "__combined__",
                    "start": 1,
                    "end": max(1, len(request.source_code.splitlines())),
                    "vulns": list(vulns),
                }

        timings["grouping_seconds"] = round(time.perf_counter() - t1, 3)
        if log_verbose:
            logger.info(f"[pipeline] grouping:end elapsed={timings['grouping_seconds']}s groups={len(group_map)}")

        # 3) 각 그룹별 슬라이스 생성
        t2 = time.perf_counter()
        if log_verbose:
            logger.info("[pipeline] slicing:start groups=%d", len(group_map))
        original_slices: List[str] = []
        grouped_meta: List[Dict[str, Any]] = []
        for (fname, s_line, e_line), meta in group_map.items():
            try:
                s = slice_function_with_header(language, request.source_code, s_line)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"슬라이싱 실패 (start {s_line}): {e}")
            original_slices.append(s)
            # 그룹 메타 구성 (CWE 리스트 등)
            cwes = sorted({int(getattr(v, 'cwe', 0) or 0) for v in meta["vulns"]})
            grouped_meta.append({
                "function_name": meta.get("name", "unknown"),
                "start": s_line,
                "end": e_line,
                "cwes": cwes,
                "count": len(meta["vulns"]),
            })
        timings["slicing_seconds"] = round(time.perf_counter() - t2, 3)
        if log_verbose:
            logger.info(f"[pipeline] slicing:end elapsed={timings['slicing_seconds']}s")

        # 4) 각 그룹별 LLM 시큐어 코딩 수행 (그룹 단위, 병렬)
        t3 = time.perf_counter()
        if log_verbose:
            logger.info("[pipeline] llm_fix:start groups=%d concurrency=%d", len(grouped_meta), llm_concurrency)
        llm = LLMService()
        sem = asyncio.Semaphore(max(1, llm_concurrency))

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

        tasks = [
            _fix_one(meta, s)
            for meta, s in zip(grouped_meta, original_slices)
        ]
        results = await asyncio.gather(*tasks)
        fixed_slices = [fx for fx, _ in results]
        llm_texts = [tx for _, tx in results]
        timings["llm_fix_seconds"] = round(time.perf_counter() - t3, 3)
        if log_verbose:
            logger.info(f"[pipeline] llm_fix:end elapsed={timings['llm_fix_seconds']}s")

        # 5) Semgrep Autofix Rule 생성
        t4 = time.perf_counter()
        if log_verbose:
            logger.info("[pipeline] rule_gen:start rule_mode=%s", rule_mode)
        sep = "// ---- slice ----\n" if language == Language.JAVA else "# ---- slice ----\n"
        semgrep_service = SemgrepRuleService()

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

        if rule_mode == "per_cwe":
            # split by CWE and create rules per CWE, return as array (no merge)
            t_split = time.perf_counter()
            by_cwe: Dict[int, Dict[str, List[str]]] = {}
            # map group index to its meta for CWE membership
            for meta, orig, fix in zip(grouped_meta, original_slices, fixed_slices):
                for c in meta.get("cwes", []):
                    bucket = by_cwe.setdefault(int(c), {"orig": [], "fix": []})
                    bucket["orig"].append(orig)
                    bucket["fix"].append(fix)
            timings["rule_cwe_split_seconds"] = round(time.perf_counter() - t_split, 3)
            if log_verbose:
                logger.info(f"[pipeline] rule_cwe_split:end elapsed={timings['rule_cwe_split_seconds']}s cwe_count={len(by_cwe)}")

            per_yaml: List[str] = []
            per_paths: List[str] = []
            sem_rules = asyncio.Semaphore(max(1, rule_concurrency))

            async def _gen_rule_one(cwe_id: int, parts: Dict[str, List[str]]) -> Tuple[int, str]:
                original_combined = (sep).join(parts["orig"])  # type: ignore[index]
                fixed_combined = (sep).join(parts["fix"])      # type: ignore[index]
                def _work() -> str:
                    resp = semgrep_service.generate_autofix_rule(
                        request=type("_Req", (), {
                            "language": language,
                            "filename": request.filename or "unknown",
                            "original_code": request.source_code,
                            "fixed_code": fixed_combined,
                            "original_slice": original_combined,
                            "fixed_slice": fixed_combined,
                            "target_cwes": [int(cwe_id)],
                        })(),
                        prompt_strategy=semgrep_prompt_strategy,
                    )
                    return resp.rule_yaml
                async with sem_rules:
                    rule_yaml = await asyncio.to_thread(_work)
                return int(cwe_id), rule_yaml

            tasks_rules = [
                _gen_rule_one(int(cwe_id), parts) for cwe_id, parts in by_cwe.items()
            ]
            results_rules = await asyncio.gather(*tasks_rules)
            # 유지 보수성을 위해 CWE id 순으로 정렬
            results_rules.sort(key=lambda x: x[0])
            per_yaml = [ry for _, ry in results_rules]
            # save to disk
            base_dir = os.environ.get("SEMGREP_RULE_OUTPUT_DIR", "semgrep_rules")
            job_dir = os.path.join(base_dir, scan_response.job_id)
            os.makedirs(job_dir, exist_ok=True)
            for cwe_id, body in zip(by_cwe.keys(), per_yaml):
                fname = f"rule_cwe-{int(cwe_id)}.yaml"
                path = os.path.join(job_dir, fname)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(body)
                per_paths.append(path)
            rule_yaml = None
            rules_yaml = per_yaml
            rules_paths = per_paths
        else:
            # single rule for all changes (current behavior)
            original_combined = (sep).join(original_slices)
            fixed_combined = (sep).join(fixed_slices)
            rule_resp = semgrep_service.generate_autofix_rule(
                request=type("_Req", (), {
                    "language": language,
                    "filename": request.filename or "unknown",
                    "original_code": request.source_code,
                    "fixed_code": fixed_combined,
                    "original_slice": original_combined,
                    "fixed_slice": fixed_combined,
                    # pass merged CWE scope hint
                    "target_cwes": sorted({int(c) for meta in grouped_meta for c in meta.get("cwes", [])}),
                })(),
                prompt_strategy=semgrep_prompt_strategy,
            )
            rule_yaml = rule_resp.rule_yaml
            rules_yaml = [rule_yaml]
            # save to disk
            base_dir = os.environ.get("SEMGREP_RULE_OUTPUT_DIR", "semgrep_rules")
            job_dir = os.path.join(base_dir, scan_response.job_id)
            os.makedirs(job_dir, exist_ok=True)
            fname = "rule_single.yaml"
            single_path = os.path.join(job_dir, fname)
            with open(single_path, "w", encoding="utf-8") as f:
                f.write(rule_yaml)
            rules_paths = [single_path]
        timings["rule_gen_seconds"] = round(time.perf_counter() - t4, 3)
        if log_verbose:
            logger.info(f"[pipeline] rule_gen:end elapsed={timings['rule_gen_seconds']}s")

        # 6) Save scan results JSON alongside rules
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
                "vulnerabilities_processed": len(vulns),
                "groups_processed": len(grouped_meta),
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
            "mode": mode,
            "vulnerabilities_processed": len(vulns),
            "groups_processed": len(grouped_meta),
            "original_slices": original_slices,
            "fixed_slices": fixed_slices,
            "llm_responses": llm_texts,
            "semgrep_rule_yaml": rule_yaml,
            "semgrep_rules_yaml": rules_yaml if rule_mode == "per_cwe" or rule_yaml else None,
            "semgrep_rule_paths": rules_paths,
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
