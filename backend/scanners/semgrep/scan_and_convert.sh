#!/bin/bash

set -e

SOURCE_PATH="${1:-/source}"
OUTPUT_FILE="${2:-/results/semgrep_result.json}"

echo "=== Running Semgrep scan ===" >&2

# Semgrep 실행
semgrep scan \
  --config=auto \
  --no-git-ignore \
  --disable-version-check \
  "$SOURCE_PATH" \
  --json \
  -o /tmp/semgrep_raw.json 2>&1 || true

# 결과가 없으면 빈 JSON 생성
if [ ! -f /tmp/semgrep_raw.json ] || [ ! -s /tmp/semgrep_raw.json ]; then
    echo "Warning: No results from Semgrep" >&2
    echo '{"scanner":"semgrep","scan_time":"2025-01-01T00:00:00","total_issues":0,"vulnerabilities":[]}' > "$OUTPUT_FILE"
    exit 0
fi

# Python 변환 스크립트를 파일로 생성
cat > /tmp/convert.py <<'PYEOF'
import json
import sys
from datetime import datetime

try:
    with open('/tmp/semgrep_raw.json', 'r', encoding='utf-8') as f:
        raw_data = json.load(f)

    vulnerabilities = []

    for finding in raw_data.get('results', []):
        extra = finding.get('extra', {})
        metadata = extra.get('metadata', {})

        # 심각도
        severity_map = {'ERROR': 'high', 'WARNING': 'medium', 'INFO': 'low'}
        severity = severity_map.get(extra.get('severity', 'WARNING'), 'medium')

        # CWE 추출 (정수)
        cwe = 0
        if 'cwe' in metadata:
            cwe_list = metadata['cwe']
            if isinstance(cwe_list, list) and len(cwe_list) > 0:
                cwe_str = str(cwe_list[0])
                if 'CWE-' in cwe_str:
                    cwe_num = cwe_str.split(':')[0].replace('CWE-', '').strip()
                    cwe = int(cwe_num) if cwe_num.isdigit() else 0

        # 파일 경로
        file_path = finding.get('path', '')

        # 라인 번호
        start_line = finding.get('start', {}).get('line', 0)
        end_line = finding.get('end', {}).get('line', start_line)

        # 코드 스니펫
        code_lines_raw = extra.get('lines', '')

        if code_lines_raw in ['requires login', '', None]:
            # 파일에서 직접 읽기
            try:
                full_path = file_path if file_path.startswith('/') else f"/source/{file_path}"
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    all_lines = f.readlines()
                snippet_start = max(0, start_line - 2)
                snippet_end = min(len(all_lines), end_line + 1)
                code_snippet = ''.join(
                    f"{i+1} {all_lines[i]}" for i in range(snippet_start, snippet_end)
                ).rstrip()
            except:
                code_snippet = f"Line {start_line}: (source not available)"
        else:
            code_lines = code_lines_raw.strip().split('\n')
            code_snippet = '\n'.join(f"{start_line + i} {line}" for i, line in enumerate(code_lines))

        vuln = {
            "scanner": "semgrep",
            "rule_id": finding.get('check_id', 'UNKNOWN'),
            "severity": severity,
            "cwe": cwe,
            "file_path": file_path,
            "line_start": start_line,
            "line_end": end_line,
            "code_snippet": code_snippet,
            "description": extra.get('message', ''),
        }
        vulnerabilities.append(vuln)

    result = {
        "scanner": "semgrep",
        "scan_time": datetime.now().isoformat(),
        "total_issues": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }

    with open('/tmp/semgrep_converted.json', 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"Converted {len(vulnerabilities)} vulnerabilities", file=sys.stderr)

except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc(file=sys.stderr)
    error_result = {
        "scanner": "semgrep",
        "scan_time": datetime.now().isoformat(),
        "total_issues": 0,
        "vulnerabilities": []
    }
    with open('/tmp/semgrep_converted.json', 'w', encoding='utf-8') as f:
        json.dump(error_result, f, indent=2, ensure_ascii=False)
    sys.exit(1)

PYEOF

# Python 스크립트 실행
python3 /tmp/convert.py

# 변환된 파일을 최종 출력 위치로 복사
if [ -f /tmp/semgrep_converted.json ]; then
    cp /tmp/semgrep_converted.json "$OUTPUT_FILE"
    echo "=== Semgrep scan completed ===" >&2
else
    echo "Error: Conversion failed" >&2
    echo '{"scanner":"semgrep","scan_time":"2025-01-01T00:00:00","total_issues":0,"vulnerabilities":[]}' > "$OUTPUT_FILE"
    exit 1
fi
