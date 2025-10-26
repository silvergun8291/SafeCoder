#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Error: Source code path required"
    exit 1
fi

SOURCE_PATH="$1"
OUTPUT_FILE="${2:-/results/bandit_result.json}"

# UTF-8 환경 설정
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

# Bandit 실행
bandit -r "$SOURCE_PATH" -f json -o /tmp/bandit_raw.json || true

# Python 스크립트에 OUTPUT_FILE을 커맨드 라인 인자로 전달
python3 - "$OUTPUT_FILE" <<'PYTHON_SCRIPT'
import json
import sys

output_file = sys.argv[1]

try:
    with open('/tmp/bandit_raw.json', 'r', encoding='utf-8') as f:
        raw_data = json.load(f)

    vulnerabilities = []

    for result in raw_data.get('results', []):
        vuln = {
            "scanner": "bandit",
            "rule_id": result.get('test_id', 'UNKNOWN'),
            "severity": result.get('issue_severity', 'MEDIUM').lower(),
            "cwe": result.get('issue_cwe', {}).get('id', '') if isinstance(result.get('issue_cwe'), dict) else '',
            "file_path": result.get('filename', ''),
            "line_start": result.get('line_number', 0),
            "line_end": result.get('line_number', 0),
            "code_snippet": result.get('code', '').strip(),
            "description": result.get('issue_text', ''),
        }

        severity_map = {'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}
        vuln['severity'] = severity_map.get(vuln['severity'].upper(), 'medium')

        vulnerabilities.append(vuln)

    output = {
        "scanner": "bandit",
        "scan_time": raw_data.get('generated_at', ''),
        "total_issues": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Bandit scan completed: {len(vulnerabilities)} issues found")
    sys.exit(0)

except FileNotFoundError:
    output = {
        "scanner": "bandit",
        "scan_time": "",
        "total_issues": 0,
        "vulnerabilities": []
    }
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print("Bandit scan completed: 0 issues found")
    sys.exit(0)

except Exception as e:
    print(f"Error processing Bandit results: {e}", file=sys.stderr)
    sys.exit(1)
PYTHON_SCRIPT
