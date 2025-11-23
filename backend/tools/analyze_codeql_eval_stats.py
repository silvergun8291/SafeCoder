import asyncio
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import docker
try:
    from tqdm import tqdm  # type: ignore
except Exception:
    tqdm = None

BASE_DIR = Path(__file__).resolve().parent.parent
STATS_FILE = BASE_DIR / "tools" / "codeql_eval_stats.txt"
EVAL_INPUT = BASE_DIR / "tools" / "secure_coding_eval.bak.txt"
WORK_DIR = BASE_DIR / "tools" / "analysis_tmp"
REPORT_TEXT = BASE_DIR / "tools" / "codeql_eval_analysis.txt"
REPORT_JSON = BASE_DIR / "tools" / "codeql_eval_analysis.json"

SEM_GREP_IMAGE = "custom/semgrep:latest"
HORUSEC_IMAGE = "custom/horusec:latest"

PARALLEL = int(os.environ.get("ANALYSIS_CONCURRENCY", "8"))


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


def parse_stats_file(stats_text: str) -> Tuple[List[int], List[int]]:
    """
    Returns (clean_cases, vulnerable_cases)
    We look for lines like:
      Case #X: Clean (0 findings)
      Case #Y: Vulnerable (N findings)
    """
    clean: List[int] = []
    vuln: List[int] = []
    for line in stats_text.splitlines():
        m = re.match(r"^Case\s+#(\d+):\s+(Clean|Vulnerable)\b", line.strip())
        if not m:
            continue
        num = int(m.group(1))
        kind = m.group(2)
        if kind == "Clean":
            clean.append(num)
        elif kind == "Vulnerable":
            vuln.append(num)
    return sorted(clean), sorted(vuln)


def parse_stats_file_with_details(stats_text: str) -> Tuple[List[int], List[int], Dict[int, List[str]]]:
    clean: List[int] = []
    vuln: List[int] = []
    details: Dict[int, List[str]] = {}
    current_case: Optional[int] = None
    current_mode: Optional[str] = None
    for raw in stats_text.splitlines():
        line = raw.rstrip("\n")
        m = re.match(r"^Case\s+#(\d+):\s+(Clean|Vulnerable)\b", line.strip())
        if m:
            num = int(m.group(1))
            kind = m.group(2)
            current_case = num
            current_mode = kind
            if kind == "Clean":
                clean.append(num)
            elif kind == "Vulnerable":
                vuln.append(num)
                details.setdefault(num, [])
            continue
        if current_mode == "Vulnerable" and line.lstrip().startswith("- "):
            if current_case is not None:
                details.setdefault(current_case, []).append(line.strip())
    return sorted(clean), sorted(vuln), details


async def write_case_source(case_dir: Path, code: str) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "Main.java").write_text(code, encoding="utf-8")


async def run_semgrep_container(source_dir: Path, results_dir: Path, timeout: int = 600) -> Tuple[int, Optional[Path], Optional[str]]:
    client = docker.from_env()
    result_json = results_dir / "semgrep_result.json"

    def _run() -> Tuple[int, str]:
        container = client.containers.run(
            image=SEM_GREP_IMAGE,
            command=["/scanner/scan_and_convert.sh", "/source", "/results/semgrep_result.json"],
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
            return status, ""
        except Exception:
            return -1, ""

    try:
        status, _ = await asyncio.to_thread(_run)
        if not result_json.exists():
            return status, None, "no semgrep result"
        return status, result_json, None
    except Exception as e:
        return -1, None, str(e)


async def run_horusec_container(source_dir: Path, results_dir: Path, timeout: int = 600) -> Tuple[int, Optional[Path], Optional[str]]:
    client = docker.from_env()
    result_json = results_dir / "horusec_result.json"

    def _run() -> Tuple[int, str]:
        container = client.containers.run(
            image=HORUSEC_IMAGE,
            command=["/source", "/results/horusec_result.json"],
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
            return status, ""
        except Exception:
            return -1, ""

    try:
        status, _ = await asyncio.to_thread(_run)
        if not result_json.exists():
            return status, None, "no horusec result"
        return status, result_json, None
    except Exception as e:
        return -1, None, str(e)


def load_json(path: Path) -> Dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def cwe_key(v: Dict) -> str:
    cwe = v.get("cwe", 0)
    if isinstance(cwe, int):
        return f"CWE-{cwe}" if cwe > 0 else "CWE-0"
    if isinstance(cwe, str) and cwe:
        return cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
    return "CWE-0"


def humanize_rule(rule_id: str) -> str:
    # Take the last path segment after '/'
    base = rule_id.split('/')[-1] if rule_id else rule_id
    # Replace separators with spaces and title-case
    name = re.sub(r"[^A-Za-z0-9]+", " ", base).strip()
    return name.title() if name else (rule_id or "Unknown")


async def analyze() -> None:
    if not STATS_FILE.exists():
        raise FileNotFoundError(f"Stats file not found: {STATS_FILE}")
    if not EVAL_INPUT.exists():
        raise FileNotFoundError(f"Eval input not found: {EVAL_INPUT}")

    stats_text = STATS_FILE.read_text(encoding="utf-8", errors="ignore")
    clean_cases, vuln_cases, vuln_details = parse_stats_file_with_details(stats_text)

    # Build case map from original eval input
    eval_text = EVAL_INPUT.read_text(encoding="utf-8", errors="ignore")
    cases = parse_eval_java_blocks(eval_text)
    case_map: Dict[int, str] = {c.case_no: c.code for c in cases}

    # Prepare workspace
    if WORK_DIR.exists():
        for child in WORK_DIR.iterdir():
            if child.is_dir():
                # best-effort cleanup; leave top WORK_DIR
                for sub in child.glob("**/*"):
                    try:
                        if sub.is_file():
                            sub.unlink(missing_ok=True)
                    except Exception:
                        pass
            try:
                if child.is_dir():
                    child.rmdir()
                else:
                    child.unlink(missing_ok=True)
            except Exception:
                pass
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    # Report structures
    semgrep_found: Dict[str, List[Dict]] = {}
    horusec_found: Dict[str, List[Dict]] = {}

    # Only rescan CLEAN cases
    targets = [c for c in clean_cases if c in case_map]

    sem = asyncio.Semaphore(max(1, PARALLEL))

    async def process_case(case_no: int):
        async with sem:
            case_dir = WORK_DIR / f"case_{case_no}"
            results_dir = case_dir / "results"
            results_dir.mkdir(parents=True, exist_ok=True)
            await write_case_source(case_dir, case_map[case_no])

            # Run both scanners concurrently per case
            # semgrep_task = asyncio.create_task(run_semgrep_container(case_dir, results_dir))
            horusec_task = asyncio.create_task(run_horusec_container(case_dir, results_dir))
            # s_status, s_path, s_err = await semgrep_task
            h_status, h_path, h_err = await horusec_task

            # Parse results
            # if s_path and s_path.exists():
            #     s_raw = load_json(s_path)
            #     for v in s_raw.get("vulnerabilities", []) or []:
            #         key = cwe_key(v)
            #         semgrep_found.setdefault(key, []).append({"case": case_no, **v})

            if h_path and h_path.exists():
                h_raw = load_json(h_path)
                for v in h_raw.get("vulnerabilities", []) or []:
                    key = cwe_key(v)
                    horusec_found.setdefault(key, []).append({"case": case_no, **v})

    tasks = [asyncio.create_task(process_case(n)) for n in targets]
    pbar = tqdm(total=len(tasks), desc="Rescan", unit="case") if tqdm else None
    for fut in asyncio.as_completed(tasks):
        await fut
        if pbar:
            pbar.update(1)
    if pbar:
        pbar.close()

    # Build reports
    REPORT_TEXT.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = []
    lines.append("CodeQL Eval Analysis Report")
    lines.append(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Stats Source: {STATS_FILE.name}")
    lines.append(f"Eval Source: {EVAL_INPUT.name}")
    lines.append("")

    # 1. 취약 케이스 코드 정리 (from eval input)
    lines.append("[1] Vulnerable cases from CodeQL (code included)")
    if vuln_cases:
        for n in vuln_cases:
            code = case_map.get(n, "")
            lines.append(f"Case #{n}:\n{code}")
            for d in vuln_details.get(n, []):
                # Try to extract rule id and prepend a humanized name
                m = re.search(r"rule=([^,\s]+)", d)
                if m:
                    rid = m.group(1)
                    name = humanize_rule(rid)
                    lines.append(f"- name={name}, {d.lstrip('- ').strip()}")
                else:
                    lines.append(d)
            lines.append("---")
    else:
        lines.append("(none)")
    lines.append("")

    # 2. 안전 케이스 코드 정리
    lines.append("[2] Clean cases from CodeQL (code included)")
    if clean_cases:
        for n in clean_cases:
            code = case_map.get(n, "")
            lines.append(f"Case #{n}:\n{code}\n---")
    else:
        lines.append("(none)")
    lines.append("")

    # 3. Semgrep & Horusec 재스캔 결과 (CWE별)
    lines.append("[3] Re-scan clean cases with Semgrep & Horusec (grouped by CWE)")
    def dump_group(title: str, grouped: Dict[str, List[Dict]]):
        lines.append(f"- {title}")
        if not grouped:
            lines.append("  (no findings)")
            return
        for cwe in sorted(grouped.keys()):
            items = grouped[cwe]
            lines.append(f"  * {cwe}: {len(items)} findings")
            for it in items:
                case = it.get("case")
                rid = it.get("rule_id")
                sev = it.get("severity")
                ls = it.get("line_start")
                le = it.get("line_end")
                desc = (it.get("description") or "").strip().replace("\n", " ")
                lines.append(f"    - case={case}, rule={rid}, severity={sev}, lines=L{ls}-{le}, desc={desc}")
    dump_group("Semgrep", semgrep_found)
    dump_group("Horusec", horusec_found)
    lines.append("")

    REPORT_TEXT.write_text("\n".join(lines), encoding="utf-8")

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "codeql": {
            "clean_cases": clean_cases,
            "vulnerable_cases": vuln_cases,
        },
        "rescans": {
            "semgrep": semgrep_found,
            "horusec": horusec_found,
        },
    }
    REPORT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    asyncio.run(analyze())
