import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

from app.models.schemas import ScanRequest, Language
from app.services.scanning.scanner_service import ScannerService
from app.services.llm_service import LLMService
from app.services.patch_service import PatchService
try:
    from tqdm import tqdm  # type: ignore
except Exception:
    tqdm = None

BASE_DIR = Path(__file__).resolve().parent.parent
TEST_SET_PATH = BASE_DIR / "tests" / "test_data" / "test_set.json"
OUTPUT_PATH = BASE_DIR / "tools" / "secure_coding_eval_baseline.txt"

CONCURRENCY = 10


def extract_code_block(text: str, lang: Language) -> str | None:
    if not text:
        return None
    return PatchService._extract_first_code_block(text, lang)


async def llm_secure_code_full(llm: LLMService, language: Language, src: str) -> str | None:
    sys_prompt = (
        "You are a secure coding assistant. You analyze code for security vulnerabilities and rewrite the full file to a secure form without changing functionality. "
        "Return only the full corrected code enclosed in a single fenced code block."
    )
    # Derive a safe language tag for fences (prefer enum value; fallback to str)
    lang_tag = str(getattr(language, "value", str(language))).lower()
    user_prompt = (
        f"Language: {lang_tag}\n"
        "1) Check if the following code has any security vulnerabilities.\n"
        "2) If vulnerabilities are found, perform secure coding and return the entire corrected code.\n"
        "3) If no vulnerabilities are found, still return the entire code as-is.\n"
        "4) Return only one fenced code block with the final full code.\n\n"
        f"```{lang_tag}\n{src}\n```\n"
    )
    return await llm.ask_async(sys_prompt, user_prompt)


async def eval_one(scanner: ScannerService, llm: LLMService, item: dict) -> Tuple[int, int, int, dict]:
    language = Language(item.get("lang", "java"))
    rejected = item.get("rejected", "")
    code = extract_code_block(rejected, language) or rejected

    scan_opts = {
        "specific_scanners": ["horusec", "semgrep", "spotbugs"],
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

    llm_resp = await llm_secure_code_full(llm, language, code)
    patched_code = extract_code_block(llm_resp or "", language) or code

    try:
        ok = PatchService._validate_syntax(language, patched_code)
        if not ok:
            patched_code = code
    except Exception:
        patched_code = code

    fixed_req = ScanRequest(
        language=language,
        source_code=patched_code,
        filename=item.get("filename", "Test.java"),
        options=scan_opts,
    )
    fixed_scan = await scanner.scan_code(fixed_req)

    before_cnt = int(getattr(initial_scan, "total_vulnerabilities", 0) or 0)
    after_cnt = int(getattr(fixed_scan, "total_vulnerabilities", 0) or 0)

    status = 0
    if after_cnt == 0:
        status = 2
    elif after_cnt < before_cnt:
        status = 1
    elif after_cnt > before_cnt:
        status = -1
    else:
        status = 0

    detail = {
        "before_vulns": before_cnt,
        "after_vulns": after_cnt,
        "fixed_code": patched_code,
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

    concurrency = max(1, int(CONCURRENCY))

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    header = [
        "Secure Coding Baseline (LLM only)",
        f"Timestamp: {datetime.now(timezone.utc).isoformat()}",
        "Scanners: horusec, semgrep, spotbugs (java)",
        "",
    ]
    OUTPUT_PATH.write_text("\n".join(header), encoding="utf-8")

    with TEST_SET_PATH.open("r", encoding="utf-8") as f:
        data = json.load(f) or []
        cases = [it for it in data if str(it.get("lang", "")).lower() == "java"]
        pbar = tqdm(total=len(cases), desc="Baseline", unit="case") if tqdm else None

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
                return case_no, await eval_one(scanner, llm, item)

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
            if status == -1:
                fixed_code = detail.get("fixed_code") or ""
                if fixed_code:
                    parts.append("Patched code (still vulnerable):")
                    parts.append("```java")
                    parts.append(fixed_code)
                    parts.append("```")
                    parts.append("")

            case_block = "\n".join(parts)
            await write_queue.put(case_block)

            if pbar:
                pbar.update(1)
                pbar.set_postfix({"clean": clean, "improved": improved, "same": same, "worse": worse}, refresh=True)

        if pbar:
            pbar.close()

        await write_queue.put(None)
        await write_queue.join()
        await writer_task

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
