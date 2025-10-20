#!/bin/sh

set -e

if [ -z "$1" ]; then
    echo "Error: Source code path required"
    exit 1
fi

SOURCE_PATH="$1"
OUTPUT_FILE="${2:-/results/horusec_result.json}"

# Horusec 실행
horusec start -p "$SOURCE_PATH" -o json -O /tmp/horusec_raw.json || true

# Python 스크립트로 표준 포맷 변환
python3 - "$OUTPUT_FILE" <<'PYTHON_SCRIPT'
import json
import sys
import os
from datetime import datetime

output_file = sys.argv[1]

try:
    if not os.path.exists('/tmp/horusec_raw.json'):
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

    vulnerabilities = []

    # Horusec analysisVulnerabilities 파싱
    analysis_vulns = raw_data.get('analysisVulnerabilities', [])

    for item in analysis_vulns:
        vuln_data = item.get('vulnerabilities', {})

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
            import re
            match = re.search(r'CWE-(\d+)', details)
            if match:
                cwe = f"CWE-{match.group(1)}"

        vuln = {
            "scanner": "horusec",
            "rule_id": vuln_data.get('securityTool', 'UNKNOWN'),
            "severity": severity,
            "cwe": cwe,
            "line_start": vuln_data.get('line', 0),
            "line_end": vuln_data.get('line', 0),
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

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"Horusec scan completed: {len(vulnerabilities)} issues found")

except Exception as e:
    print(f"Error: {e}")
    error_result = {
        "scanner": "horusec",
        "scan_time": datetime.now().isoformat(),
        "total_issues": 0,
        "vulnerabilities": []
    }
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(error_result, f, indent=2, ensure_ascii=False)
    sys.exit(1)

PYTHON_SCRIPT
