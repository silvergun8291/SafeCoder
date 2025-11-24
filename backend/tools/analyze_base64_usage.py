import json
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
TEST_SET_PATH = BASE_DIR / "tests" / "test_data" / "test_set.json"
EVAL_PATH = BASE_DIR / "tools" / "secure_coding_evaluation.txt"
OUT_PATH = BASE_DIR / "tools" / "base64_analysis.txt"

CASE_RE = re.compile(r"^Case\s+#(\d+)")
BASE64_RE = re.compile(r"base64", re.IGNORECASE)
REASON_RE = re.compile(r"^\s*Reason:\s*(.*)$", re.IGNORECASE)
LINES_RE = re.compile(r"Lines=\s*L(\d+)-(\d+)")
SCANNER_RE = re.compile(r"Scanner=([^,]+)")

NEC_HINTS = [
    "encrypted", "cipher", "iv,", "nonce", "SecureRandom", "combined", "output =", "encodeToString(combined)",
]
HASH_HINTS = ["SHA-256", "MessageDigest", "hash", "digest",]
ID_HINTS = ["errorId", "getUrlEncoder", "withoutPadding",]


def load_java_cases():
    data = json.loads(TEST_SET_PATH.read_text(encoding="utf-8"))
    java_cases = [it for it in data if str(it.get("lang", "")).lower() == "java"]
    return java_cases


def analyze():
    java_cases = load_java_cases()
    lines = EVAL_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()

    results = []
    cur_case = None
    buf = []

    def flush_case(case_no):
        if case_no is None:
            return
        # parse buf for Base64 entries
        entries = []
        for i, ln in enumerate(buf):
            if BASE64_RE.search(ln):
                # try to find metadata lines around
                reason = None
                scanner = None
                line_range = None
                # look backwards a bit
                for j in range(max(0, i-5), min(len(buf), i+10)):
                    m = REASON_RE.search(buf[j])
                    if m:
                        reason = m.group(1).strip()
                    m2 = SCANNER_RE.search(buf[j])
                    if m2:
                        scanner = m2.group(1).strip()
                    m3 = LINES_RE.search(buf[j])
                    if m3:
                        line_range = (int(m3.group(1)), int(m3.group(2)))
                entries.append({
                    "index": i,
                    "line": ln.strip(),
                    "reason": reason,
                    "scanner": scanner,
                    "line_range": line_range,
                })
        if not entries:
            return
        # original code presence
        orig = java_cases[case_no-1].get("rejected", "") if 1 <= case_no <= len(java_cases) else ""
        orig_has_base64 = bool(BASE64_RE.search(orig))
        # classify necessity heuristically
        necessity = "unknown"
        context = "\n".join(buf)
        ctx_lower = context.lower()
        def has_any(hints):
            return any(h.lower() in ctx_lower for h in hints)
        if has_any(NEC_HINTS):
            necessity = "likely_needed_for_transport"
        if has_any(HASH_HINTS):
            necessity = "maybe_unnecessary_for_hash_display"
        if has_any(ID_HINTS):
            # opaque id textification is usually ok
            necessity = "acceptable_for_id_text"
        results.append({
            "case": case_no,
            "orig_has_base64": orig_has_base64,
            "entries": entries,
            "necessity": necessity,
        })

    # stream and accumulate per case
    for ln in lines:
        m = CASE_RE.match(ln.strip())
        if m:
            # flush previous
            flush_case(cur_case)
            cur_case = int(m.group(1))
            buf = []
            continue
        if cur_case is not None:
            buf.append(ln)
    flush_case(cur_case)

    # write report
    out = []
    out.append("Base64 usage analysis")
    out.append("====================\n")
    for r in results:
        out.append(f"Case #{r['case']}")
        out.append(f"- Original contained Base64: {r['orig_has_base64']}")
        out.append(f"- Necessity (heuristic): {r['necessity']}")
        out.append("- Occurrences:")
        for e in r["entries"]:
            occ = []
            if e.get("scanner"):
                occ.append(f"scanner={e['scanner']}")
            if e.get("line_range"):
                s, t = e["line_range"]
                occ.append(f"lines=L{s}-{t}")
            if e.get("reason"):
                occ.append(f"reason={e['reason']}")
            meta = ", ".join(occ) if occ else ""
            out.append(f"  - {meta}")
        out.append("")
    OUT_PATH.write_text("\n".join(out), encoding="utf-8")
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    analyze()
