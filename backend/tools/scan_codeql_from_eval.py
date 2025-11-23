import asyncio
import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple, Optional, Dict
import docker  # use the same container runtime as existing scanners
try:
    from tqdm import tqdm  # type: ignore
except Exception:
    tqdm = None

# Config
BASE_DIR = Path(__file__).resolve().parent.parent
EVAL_INPUT = BASE_DIR / "tools" / "secure_coding_eval.bak.txt"
WORK_DIR = BASE_DIR / "tools" / "codeql_tmp"
OUTPUT_SUMMARY = BASE_DIR / "tools" / "codeql_eval_stats.txt"
CONCURRENCY = 4  # adjust parallel container workers
CODEQL_IMAGE = "custom/codeql:latest"  # match existing config

@dataclass
class JavaCase:
    case_no: int
    code: str


def parse_eval_java_blocks(text: str) -> List[JavaCase]:
    cases: List[JavaCase] = []
    current_case: Optional[int] = None
    in_code = False
    code_lines: List[str] = []

    case_re = re.compile(r"^Case\s+#(\d+)")
    code_start_re = re.compile(r"^```\s*java\s*$", re.IGNORECASE)
    code_end_re = re.compile(r"^```\s*$")

    for line in text.splitlines():
        m_case = case_re.match(line.strip())
        if m_case and not in_code:
            try:
                current_case = int(m_case.group(1))
            except Exception:
                current_case = None
            continue
        if not in_code and code_start_re.match(line):
            in_code = True
            code_lines = []
            continue
        if in_code and code_end_re.match(line):
            in_code = False
            if current_case is not None:
                code = "\n".join(code_lines).strip()
                if code:
                    cases.append(JavaCase(case_no=current_case, code=code))
            code_lines = []
            continue
        if in_code:
            code_lines.append(line)
    return cases


async def run_cmd(cmd: List[str], cwd: Path | None = None, env: Dict[str, str] | None = None, timeout: int = 900) -> Tuple[int, str, str]:
    # retained for potential future local commands (unused in container mode)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=0x08000000 if os.name == 'nt' else 0,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return 124, "", f"Timeout running: {' '.join(cmd)}"
        return proc.returncode or 0, out.decode(errors='ignore'), err.decode(errors='ignore')
    except Exception as e:
        return 1, "", str(e)


async def run_codeql_container(source_dir: Path, results_dir: Path, timeout: int = 1800) -> Tuple[int, Optional[Path], Optional[str]]:
    """
    Run the existing custom/codeql:latest container to scan the given source directory.
    Uses java mode with build-mode=none (inside container entrypoint).
    Returns (exit_code, result_json_path, error_message)
    """
    client = docker.from_env()
    result_json = results_dir / "codeql_result.json"

    def _run() -> Tuple[int, str]:
        container = client.containers.run(
            image=CODEQL_IMAGE,
            command=["/source", "/results/codeql_result.json", "java"],
            volumes={
                str(source_dir): {"bind": "/source", "mode": "rw"},
                str(results_dir): {"bind": "/results", "mode": "rw"},
            },
            detach=True,
            remove=True,
            tty=False,
            stdin_open=False,
        )
        try:
            res = container.wait(timeout=timeout)
            status = int(res.get("StatusCode", -1))
            # Avoid reading logs on Windows to prevent pipe ended errors
            logs = ""
            return status, logs
        except Exception:
            # Best-effort status; if wait fails, indicate unknown
            return -1, ""

    try:
        status, logs = await asyncio.to_thread(_run)
        if not result_json.exists():
            return status if status is not None else -1, None, f"no result file: {logs[:200]}"
        return status, result_json, None
    except Exception as e:
        return -1, None, str(e)


def parse_sarif_count(path: Path) -> int:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        runs = data.get("runs", [])
        total = 0
        for r in runs:
            results = r.get("results", [])
            total += len(results or [])
        return int(total)
    except Exception:
        return -1


async def prepare_project(case_dir: Path, java_code: str) -> Path:
    # Place a single Java file at the project root, matching container's single-file handling
    case_dir.mkdir(parents=True, exist_ok=True)
    java_path = case_dir / "Main.java"
    java_path.write_text(java_code, encoding="utf-8")
    return case_dir


async def process_case(case: JavaCase, sem: asyncio.Semaphore) -> Tuple[int, int, Optional[str], Optional[List[Dict[str, object]]], str]:
    async with sem:
        case_dir = WORK_DIR / f"case_{case.case_no}"
        results_dir = case_dir / "results"
        try:
            if case_dir.exists():
                shutil.rmtree(case_dir)
            case_dir.mkdir(parents=True, exist_ok=True)
            await prepare_project(case_dir, case.code)

            results_dir.mkdir(exist_ok=True)
            exit_code, json_path, err = await run_codeql_container(case_dir, results_dir)
            if err is not None:
                return case.case_no, -1, err, None, case.code

            try:
                raw = json.loads(json_path.read_text(encoding="utf-8")) if json_path else {}
                cnt = int(raw.get("total_issues", 0))
                vulns = raw.get("vulnerabilities", []) or []
            except Exception as e:
                return case.case_no, -1, f"parse_error: {e}", None, case.code
            return case.case_no, cnt, None, vulns, case.code
        except Exception as e:
            return case.case_no, -1, str(e), None, case.code


async def main() -> None:
    # Read input
    if not EVAL_INPUT.exists():
        raise FileNotFoundError(f"Input not found: {EVAL_INPUT}")
    text = EVAL_INPUT.read_text(encoding="utf-8", errors="ignore")
    blocks = parse_eval_java_blocks(text)

    OUTPUT_SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    header = [
        "CodeQL Scan from secure_coding_eval.bak.txt",
        f"Timestamp: {datetime.now(timezone.utc).isoformat()}",
        f"Input: {EVAL_INPUT.name}",
        "Suite: java-security-extended.qls",
        "",
    ]
    OUTPUT_SUMMARY.write_text("\n".join(header), encoding="utf-8")

    sem = asyncio.Semaphore(max(1, int(CONCURRENCY)))
    tasks = [asyncio.create_task(process_case(c, sem)) for c in blocks]

    clean_cases: List[int] = []
    vuln_cases: List[int] = []
    errors: List[Tuple[int, str]] = []

    pbar = tqdm(total=len(tasks), desc="CodeQL", unit="case") if tqdm else None

    for fut in asyncio.as_completed(tasks):
        case_no, cnt, err, vulns, code_text = await fut
        if err is not None or cnt < 0:
            errors.append((case_no, err or "unknown_error"))
            with OUTPUT_SUMMARY.open("a", encoding="utf-8") as wf:
                wf.write(f"Case #{case_no}: ERROR - {err or 'unknown_error'}\n")
        elif cnt == 0:
            clean_cases.append(case_no)
            with OUTPUT_SUMMARY.open("a", encoding="utf-8") as wf:
                wf.write(f"Case #{case_no}: Clean (0 findings)\n")
                wf.write("--- Clean Case Code Begin ---\n")
                wf.write(f"Case #{case_no} Code:\n")
                wf.write(code_text)
                wf.write("\n--- Clean Case Code End ---\n")
        else:
            vuln_cases.append(case_no)
            with OUTPUT_SUMMARY.open("a", encoding="utf-8") as wf:
                wf.write(f"Case #{case_no}: Vulnerable ({cnt} findings)\n")
                try:
                    for v in (vulns or []):
                        rid = v.get("rule_id", "unknown")
                        ls = v.get("line_start", 0)
                        le = v.get("line_end", ls)
                        sev = v.get("severity", "")
                        wf.write(f"  - rule={rid}, severity={sev}, lines=L{ls}-{le}\n")
                except Exception:
                    pass

        if pbar:
            pbar.update(1)

    if pbar:
        pbar.close()

    summary = [
        f"Total code blocks: {len(blocks)}",
        f"Clean (0 findings): {len(clean_cases)}",
        f"Vulnerable (>0 findings): {len(vuln_cases)}",
        f"Errors: {len(errors)}",
        "",
        "Clean cases:",
        ", ".join(map(str, sorted(clean_cases))) or "(none)",
        "",
        "Vulnerable cases:",
        ", ".join(map(str, sorted(vuln_cases))) or "(none)",
        "",
        "Errors (case: reason):",
        ", ".join(f"{c}:{e}" for c, e in sorted(errors)) or "(none)",
        "",
    ]
    with OUTPUT_SUMMARY.open("a", encoding="utf-8") as wf:
        wf.write("\n".join(summary))


if __name__ == "__main__":
    asyncio.run(main())
