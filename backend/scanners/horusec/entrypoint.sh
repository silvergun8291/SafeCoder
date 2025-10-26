#!/bin/sh
set -e

if [ -z "$1" ]; then
    echo "Error: Source code path required"
    exit 1
fi

SOURCE_PATH="$1"
OUTPUT_FILE="${2:-/results/horusec_result.json}"

echo "========================================" >&2
echo "[Horusec] Starting scan..." >&2
echo "[Horusec] Source: $SOURCE_PATH" >&2
echo "[Horusec] Output: $OUTPUT_FILE" >&2
echo "========================================" >&2

# Horusec 실행
horusec start -p "$SOURCE_PATH" -o json -O /tmp/horusec_raw.json --disable-docker 2>&1 || true

echo "" >&2
echo "[Horusec] Scan completed. Processing results..." >&2

# 원본 JSON 출력
if [ -f /tmp/horusec_raw.json ]; then
    echo "========================================" >&2
    echo "[Horusec] Raw JSON output:" >&2
    echo "========================================" >&2
    cat /tmp/horusec_raw.json >&2
    echo "" >&2
else
    echo "[Horusec] ERROR: Raw JSON file not found!" >&2
fi

# Python 스크립트로 표준 포맷 변환
python3 - "$OUTPUT_FILE" <<'PYTHON_SCRIPT'
import json
import sys
import os
import re
from datetime import datetime

output_file = sys.argv[1]

print("========================================", file=sys.stderr)
print("[Horusec] Python parsing started...", file=sys.stderr)
print("========================================", file=sys.stderr)

try:
    if not os.path.exists('/tmp/horusec_raw.json'):
        print("[Horusec] ERROR: /tmp/horusec_raw.json not found!", file=sys.stderr)
        result = {
            "scanner": "horusec",
            "scan_time": datetime.now().isoformat(),
            "total_issues": 0,
            "vulnerabilities": []
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        sys.exit(0)

    with open('/tmp/horusec_raw.json', 'r', encoding='utf-8') as f:
        raw_data = json.load(f)

    print(f"[Horusec] Raw data keys: {list(raw_data.keys())}", file=sys.stderr)

    vulnerabilities = []
    analysis_vulns = raw_data.get('analysisVulnerabilities', [])

    print(f"[Horusec] Found {len(analysis_vulns)} analysis items", file=sys.stderr)

    for idx, item in enumerate(analysis_vulns):
        vuln_data = item.get('vulnerabilities', {})

        if not vuln_data:
            print(f"[Horusec] Item {idx}: Empty vulnerability data, skipping", file=sys.stderr)
            continue

        print(f"[Horusec] Item {idx}: {vuln_data.get('securityTool', 'UNKNOWN')} - {vuln_data.get('severity', 'UNKNOWN')}", file=sys.stderr)

        # 심각도 매핑
        severity_map = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low',
            'INFO': 'low',
            'UNKNOWN': 'medium'
        }

        severity = severity_map.get(
            vuln_data.get('severity', 'MEDIUM').upper(),
            'medium'
        )

        # CWE 추출
        cwe = ''
        details = vuln_data.get('details', '')
        if 'CWE-' in details:
            match = re.search(r'CWE-(\d+)', details)
            if match:
                cwe = f"CWE-{match.group(1)}"

        # line 필드를 정수로 변환
        try:
            line_num = int(vuln_data.get('line', 0))
        except (ValueError, TypeError):
            line_num = 0

        vuln = {
            "scanner": "horusec",
            "rule_id": vuln_data.get('securityTool', 'UNKNOWN'),
            "severity": severity,
            "cwe": cwe,
            "file_path": vuln_data.get('file', ''),
            "line_start": line_num,
            "line_end": line_num,
            "code_snippet": vuln_data.get('code', '').strip(),
            "description": details
        }
        vulnerabilities.append(vuln)

    result = {
        "scanner": "horusec",
        "scan_time": datetime.now().isoformat(),
        "total_issues": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }

    print("========================================", file=sys.stderr)
    print(f"[Horusec] Parsed result:", file=sys.stderr)
    print(f"[Horusec] Total issues: {len(vulnerabilities)}", file=sys.stderr)
    print("========================================", file=sys.stderr)
    print(json.dumps(result, indent=2, ensure_ascii=False), file=sys.stderr)
    print("========================================", file=sys.stderr)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"[Horusec] ✅ Successfully wrote {len(vulnerabilities)} issues to {output_file}", file=sys.stderr)

except Exception as e:
    print(f"[Horusec] ❌ ERROR: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc(file=sys.stderr)

    error_result = {
        "scanner": "horusec",
        "scan_time": datetime.now().isoformat(),
        "total_issues": 0,
        "vulnerabilities": []
    }
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(error_result, f, indent=2, ensure_ascii=False)
PYTHON_SCRIPT

echo "[Horusec] Processing completed." >&2
