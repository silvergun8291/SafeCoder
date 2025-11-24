import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, List, Any

from app.models.schemas import ScanRequest, Language
from app.services.scanning.scanner_service import ScannerService
from app.services.llm_service import LLMService
from app.services.patch_service import PatchService
try:
    from tqdm import tqdm  # type: ignore
except Exception:
    tqdm = None  # progress bar optional

# Resolve paths relative to backend root regardless of CWD
BASE_DIR = Path(__file__).resolve().parent.parent
TEST_SET_PATH = BASE_DIR / "tests" / "test_data" / "test_set.json"
OUTPUT_PATH = BASE_DIR / "tools" / "secure_coding_evaluation_ver3.txt"

CONCURRENCY = 10


def extract_code_block(text: str, lang: Language) -> str | None:
    if not text:
        return None
    return PatchService._extract_first_code_block(text, lang)


def _filter_false_positives(vulns: List[Any]) -> Tuple[List[Any], List[str]]:
    kept: List[Any] = []
    fps: List[str] = []
    for v in (vulns or []):
        try:
            scanner = str(getattr(v, "scanner", "")).lower()
            cwe = int(getattr(v, "cwe", 0) or 0)
            rule_id = str(getattr(v, "rule_id", "") or "")
            desc = str(getattr(v, "description", "") or "")
            code = str(getattr(v, "code_snippet", "") or "")
            refs = getattr(v, "references", []) or []
            refs_text = " | ".join(map(str, refs))

            # Rule 1: Semgrep CWE-78 → ignore
            if scanner == "semgrep" and cwe == 78:
                fps.append(f"semgrep CWE-78 rule={rule_id}")
                continue

            # Rule 2: Horusec CWE-0 and 'import javax.crypto' issue → ignore
            text_all = " ".join([desc, code, refs_text]).lower()
            if scanner == "horusec" and cwe == 0 and ("import javax.crypto" in text_all or "javax.crypto" in text_all):
                fps.append(f"horusec CWE-0 javax.crypto rule={rule_id}")
                continue

            # Rule 3: Narrow FP - Potential Hard-coded credential only when env/args patterns present
            # 테스트/예제 코드의 실제 하드코딩은 유지하고, 환경변수/프로그램 인자 사용 패턴만 오탐으로 처리
            if "potential hard-coded credential" in text_all:
                code_lc = code.lower()
                uses_env_or_args = (
                    ("system.getenv(" in code_lc) or
                    ("env.get(" in code_lc) or  # defensive: other env accessors
                    ("args[" in code_lc) or
                    ("args." in code_lc) or
                    ("getenv(" in code_lc)
                )
                if uses_env_or_args:
                    fps.append(f"generic FP (env/args): potential hard-coded credential rule={rule_id}")
                    continue

            # Rule 4: Horusec CWE-0 Base64 Encode/Decode — acceptable patterns
            #  - errorId 생성: Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes)
            #  - 암호문 전송: encodeToString(combined/output) 또는 (encrypted/cipher + iv/nonce) 컨텍스트
            #  - "Encoding for transport only" 주석이 있는 경우
            #  - AES/GCM 암호화 결과를 Base64로 운반하는 경우
            if scanner == "horusec" and cwe == 0 and ("base64 encode" in text_all or "base64 decode" in text_all):
                is_error_id = (
                    "geturlencoder" in text_all and "withoutpadding" in text_all and (
                        "randombytes" in text_all or "securerandom" in text_all
                    )
                )
                is_ciphertext_transport = (
                    ("encodetostring" in text_all and ("combined" in text_all or "output" in text_all))
                    or ( ("encrypted" in text_all or "cipher" in text_all) and ("iv" in text_all or "nonce" in text_all) )
                )
                has_transport_only_comment = ("encoding for transport only" in text_all)
                aes_gcm_context = ("aes" in text_all and ("gcm" in text_all or "galois" in text_all)) or "cipher.getinstance" in text_all
                # True positive guard: decoding keys/secrets should NOT be ignored
                decodes_secret = ("getdecoder" in text_all and any(w in text_all for w in ["encryption_key", "secret", "key"]))
                if (is_error_id or is_ciphertext_transport or has_transport_only_comment or aes_gcm_context) and not decodes_secret:
                    fps.append(f"horusec CWE-0 base64 acceptable pattern rule={rule_id}")
                    continue

            # Rule 5: CWE-209 Information Exposure — allow when only opaque errorId is logged
            # 에러 로그에 예외 클래스/메시지 없이 errorId(예: UUID)만 포함되고, 상세는 내부 수집기로 전송하는 패턴은 오탐으로 간주
            if cwe == 209:
                code_lc = code.lower()
                logs_error_id_only = (
                    ("errorid" in code_lc or "error id" in code_lc) and
                    ("e.getmessage" not in code_lc) and ("e.getclass" not in code_lc) and ("printstacktrace" not in code_lc)
                )
                if logs_error_id_only:
                    fps.append(f"cwe-209 acceptable logging pattern rule={rule_id}")
                    continue

            kept.append(v)
        except Exception:
            kept.append(v)
    return kept, fps


async def eval_one(scanner: ScannerService, llm: LLMService, item: dict, enable_inner_bar: bool = True) -> Tuple[int, int, int, dict]:
    language = Language(item.get("lang", "java"))
    rejected = item.get("rejected", "")
    code = extract_code_block(rejected, language) or rejected

    scan_opts = {
        "min_severity": "low",
        "timeout": 300,
    }

    initial_req = ScanRequest(
        language=language,
        source_code=code,
        filename=item.get("filename", "Test.java"),
        options=scan_opts,
    )
    initial_scan = await scanner.scan_code(initial_req)

    # Per-case granular progress bar via PatchService callback
    case_bar = None
    stage_total = 11 if tqdm else 0  # approx: init(2) + first_fix(1) + 3 iters*(rescan+fix=2*3=6) + diff/apply/done(3)
    progressed = {"count": 0}

    def _bump(stage: str) -> None:
        if case_bar is not None:
            case_bar.update(1)

    def progress_cb(stage: str, info: dict) -> None:
        # Map stages to bar increments and live postfix
        incr_stages = {"initial_scan_done", "first_fix_ready", "iteration_rescan_done", "iteration_fix_done", "diff_done", "apply_done", "done"}
        if stage in incr_stages:
            _bump(stage)
        if case_bar is not None:
            postfix = {}
            if stage.startswith("iteration"):
                postfix["iter"] = info.get("iteration")
            if "vulns" in info:
                postfix["vulns"] = info.get("vulns")
            if "mode" in info:
                postfix["mode"] = info.get("mode")
            case_bar.set_postfix(postfix, refresh=True)

    if tqdm and enable_inner_bar:
        case_bar = tqdm(total=stage_total, desc="  stages", leave=False, unit="step")

    service = PatchService(scanner, progress_callback=progress_cb)
    patch_result = await service.run_patch(
        request=initial_req,
        max_iterations=3,
        min_severity="low",
        use_rag=False,
    )
    if case_bar is not None:
        case_bar.close()
    fixed_code = patch_result.get("patched_code") or code

    fixed_req = ScanRequest(
        language=language,
        source_code=fixed_code,
        filename=item.get("filename", "Test.java"),
        options=scan_opts,
    )
    fixed_scan = await scanner.scan_code(fixed_req)

    # Hybrid fallback: if vulnerabilities remain, try full-file rewrite and patch minimally via diff
    hybrid_used = False
    if int(getattr(fixed_scan, "total_vulnerabilities", 0) or 0) > 0:
        try:
            prompt = scanner.generate_secure_code_prompt(
                aggregated_vulnerabilities=getattr(initial_scan, "aggregated_vulnerabilities", None),
                source_code=code,
                language=language,
            )
            full_answer = await llm.ask_async(prompt.system_prompt, prompt.user_prompt)
            full_fixed = PatchService._extract_first_code_block(full_answer or "", language) or code
            ok, _err = PatchService._validate_syntax(full_fixed, language)
            if ok:
                # minimal patch via diff
                unified = PatchService._unified_diff(code, full_fixed, item.get("filename", "Test.java"))
                minimally_patched = PatchService._apply_patch_with_whatthepatch(code, unified) or full_fixed
                hybrid_req = ScanRequest(
                    language=language,
                    source_code=minimally_patched,
                    filename=item.get("filename", "Test.java"),
                    options=scan_opts,
                )
                hybrid_scan = await scanner.scan_code(hybrid_req)
                if int(getattr(hybrid_scan, "total_vulnerabilities", 0) or 0) <= int(getattr(fixed_scan, "total_vulnerabilities", 0) or 0):
                    fixed_code = minimally_patched
                    fixed_scan = hybrid_scan
                    hybrid_used = True
        except Exception:
            pass

    # Apply False Positive filtering for counts and reporting
    init_vulns = list(getattr(initial_scan, "aggregated_vulnerabilities", []) or [])
    fix_vulns = list(getattr(fixed_scan, "aggregated_vulnerabilities", []) or [])
    init_kept, init_fps = _filter_false_positives(init_vulns)
    fix_kept, fix_fps = _filter_false_positives(fix_vulns)

    before_cnt = len(init_kept)
    after_cnt = len(fix_kept)

    status = 0
    if after_cnt == 0:
        status = 2
    elif after_cnt < before_cnt:
        status = 1
    elif after_cnt > before_cnt:
        status = -1
    else:
        status = 0

    # Helper: build contextual code snippet around line range from given text
    def _context_from_text(text: str, start: int, end: int, pad: int = 3) -> str:
        try:
            lines = (text or "").splitlines()
            if start <= 0 and end <= 0:
                return "\n".join(lines[: min(len(lines), 20)])
            s = max(1, (start or 1) - pad)
            e = min(len(lines), (end or start or 1) + pad)
            # 1-indexed to 0-indexed slice
            block = lines[s - 1 : e]
            # Prefix with line numbers for clarity
            numbered = [f"{i+ s:>5}: {ln}" for i, ln in enumerate(block)]
            return "\n".join(numbered)
        except Exception:
            return text or ""

    # Build remaining vulnerability details (post-filter)
    remaining_details = []
    if after_cnt > 0:
        for v in fix_kept:
            try:
                remaining_details.append({
                    "scanner": getattr(v, "scanner", None),
                    "cwe": int(getattr(v, "cwe", 0) or 0),
                    "line_start": int(getattr(v, "line_start", 0) or 0),
                    "line_end": int(getattr(v, "line_end", 0) or 0),
                    # Prefer contextual snippet from the current fixed_code text using line range
                    "code_snippet": _context_from_text(
                        fixed_code,
                        int(getattr(v, "line_start", 0) or 0),
                        int(getattr(v, "line_end", 0) or 0),
                        pad=3,
                    ) or (getattr(v, "code_snippet", "") or ""),
                    "reason": getattr(v, "description", "") or getattr(v, "rule_id", ""),
                })
            except Exception:
                continue

    detail = {
        "question": item.get("question"),
        "before_vulns": before_cnt,
        "after_vulns": after_cnt,
        "initial_cwes": [int(getattr(v, "cwe", 0) or 0) for v in (getattr(initial_scan, "aggregated_vulnerabilities", []) or []) if getattr(v, "cwe", None) is not None],
        "final_cwes": [int(getattr(v, "cwe", 0) or 0) for v in (getattr(fixed_scan, "aggregated_vulnerabilities", []) or []) if getattr(v, "cwe", None) is not None],
        "fixed_code": fixed_code,
        "hybrid_used": hybrid_used,
        "false_positives": sorted(set(init_fps + fix_fps)),
        "remaining_vulnerabilities": remaining_details,
    }
    return before_cnt, after_cnt, status, detail


async def main() -> None:
    scanner = ScannerService()
    llm = LLMService()

    total = 0
    improved = 0
    clean = 0
    worse = 0
    same = 0
    lines: list[str] = []

    concurrency = max(1, int(CONCURRENCY))

    # 초기 헤더를 즉시 파일에 기록하여 중단 시에도 메타가 남도록 함
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    header = [
        "Secure Coding Evaluation",
        f"Timestamp: {datetime.now(timezone.utc).isoformat()}",
        "Scanners: horusec, semgrep, spotbugs (java)",
        "",
    ]
    OUTPUT_PATH.write_text("\n".join(header), encoding="utf-8")

    with TEST_SET_PATH.open("r", encoding="utf-8") as f:
        data = json.load(f) or []
        cases = [it for it in data if str(it.get("lang", "")).lower() == "java"]
        pbar = tqdm(total=len(cases), desc="Evaluating", unit="case") if tqdm else None

        # Writer task with queue to serialize file writes
        write_queue: asyncio.Queue[str | None] = asyncio.Queue()

        async def writer():
            while True:
                msg = await write_queue.get()
                if msg is None:
                    write_queue.task_done()
                    break
                with OUTPUT_PATH.open("a", encoding="utf-8") as wf:
                    wf.write(msg)
                write_queue.task_done()

        writer_task = asyncio.create_task(writer())

        sem = asyncio.Semaphore(concurrency)

        async def worker(case_no: int, item: dict):
            async with sem:
                return case_no, await eval_one(scanner, llm, item, enable_inner_bar=(concurrency == 1))

        tasks = [asyncio.create_task(worker(i, item)) for i, item in enumerate(cases, start=1)]

        for fut in asyncio.as_completed(tasks):
            case_no, result = await fut
            before_cnt, after_cnt, status, detail = result

            total += 1
            if status == 2:
                clean += 1
            elif status == 1:
                improved += 1
            elif status == -1:
                worse += 1
            else:
                same += 1

            parts = [
                f"Case #{case_no}",
                f"- Before: {before_cnt}",
                f"- After:  {after_cnt}",
                f"- Status: {'CLEAN' if status==2 else 'IMPROVED' if status==1 else 'WORSE' if status==-1 else 'SAME'}",
                "",
            ]
            fps = list(detail.get("false_positives") or [])
            if fps:
                parts.append("False Positives:")
                for fp in fps:
                    parts.append(f"- {fp}")
                parts.append("")
            # If still vulnerable, list remaining issues with details
            if after_cnt > 0:
                rem = list(detail.get("remaining_vulnerabilities") or [])
                if rem:
                    parts.append("Remaining vulnerabilities:")
                    for i, rv in enumerate(rem, 1):
                        line_range = f"L{rv.get('line_start', 0)}-{rv.get('line_end', 0)}"
                        parts.append(f"- [{i}] Scanner={rv.get('scanner')}, CWE-{rv.get('cwe')}, Lines={line_range}")
                        reason = str(rv.get('reason') or "").strip()
                        if reason:
                            parts.append(f"  Reason: {reason}")
                        code_snip = rv.get('code_snippet') or ""
                        if code_snip:
                            parts.append("  Code snippet:")
                            parts.append("  ```")
                            # indent snippet lines for readability
                            for ln in str(code_snip).splitlines():
                                parts.append(f"  {ln}")
                            parts.append("  ```")
                    parts.append("")

            case_block = "\n".join(parts)
            await write_queue.put(case_block)

            if pbar:
                pbar.update(1)
                pbar.set_postfix({"clean": clean, "improved": improved, "same": same, "worse": worse}, refresh=True)

        if pbar:
            pbar.close()

        # Stop writer
        await write_queue.put(None)
        await write_queue.join()
        await writer_task

    # 마지막에 요약을 append (중단 시에도 앞선 케이스 결과는 남아있음)
    summary = [
        "Summary",
        "=====",
        f"Total:    {total}",
        f"Clean:    {clean}",
        f"Improved: {improved}",
        f"Same:     {same}",
        f"Worse:    {worse}",
        "",
    ]
    with OUTPUT_PATH.open("a", encoding="utf-8") as wf:
        wf.write("\n".join(summary))


if __name__ == "__main__":
    asyncio.run(main())
