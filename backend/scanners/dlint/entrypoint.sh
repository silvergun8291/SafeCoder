#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Error: Source code path required"
    exit 1
fi

SOURCE_PATH="$1"
OUTPUT_FILE="${2:-/results/dlint_result.json}"

# UTF-8 환경 설정
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

# Flake8 + Dlint 실행
flake8 --select=DUO "$SOURCE_PATH" --format='%(path)s:%(row)d:%(col)d: %(code)s %(text)s' > /tmp/dlint_raw.txt || true

# Python 스크립트에 OUTPUT_FILE을 커맨드 라인 인자로 전달
python3 - "$OUTPUT_FILE" <<'PYTHON_SCRIPT'
import json
import sys
import os
import re
from datetime import datetime

output_file = sys.argv[1]

try:
    vulnerabilities = []

    if os.path.exists('/tmp/dlint_raw.txt'):
        with open('/tmp/dlint_raw.txt', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                match = re.match(r'^(.+?):(\d+):(\d+):\s*(\w+)\s+(.+)$', line)
                if match:
                    filepath, line_num, col, code, message = match.groups()

                    severity = 'medium'
                    if code in ['DUO105', 'DUO106', 'DUO107', 'DUO108']:
                        severity = 'high'
                    elif code in ['DUO101', 'DUO102']:
                        severity = 'critical'

                    vuln = {
                        "scanner": "dlint",
                        "rule_id": code,
                        "severity": severity,
                        "cwe": "",
                        "file_path": filepath,
                        "line_start": int(line_num),
                        "line_end": int(line_num),
                        "code_snippet": "",
                        "description": message,
                    }

                    vulnerabilities.append(vuln)

    output = {
        "scanner": "dlint",
        "scan_time": datetime.now().isoformat(),
        "total_issues": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Dlint scan completed: {len(vulnerabilities)} issues found")
    sys.exit(0)

except Exception as e:
    print(f"Error processing Dlint results: {e}", file=sys.stderr)
    output = {
        "scanner": "dlint",
        "scan_time": datetime.now().isoformat(),
        "total_issues": 0,
        "vulnerabilities": []
    }
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    sys.exit(0)
PYTHON_SCRIPT
