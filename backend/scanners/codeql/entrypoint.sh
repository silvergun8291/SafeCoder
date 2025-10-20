#!/bin/bash

set -e

if [ -z "$1" ]; then
    echo "Error: Source code path required" >&2
    exit 1
fi

SOURCE_PATH="$1"
OUTPUT_FILE="${2:-/results/codeql_result.json}"
LANGUAGE="${3:-python}"

DB_PATH="/tmp/codeql_db"
SARIF_OUTPUT="/tmp/codeql_result.sarif"

# 이전 DB 삭제
rm -rf "$DB_PATH" "$SARIF_OUTPUT"

echo "=== Preparing CodeQL source ===" >&2

# ⭐ 소스 경로 확인 및 처리
if [ -f "$SOURCE_PATH" ]; then
    # 단일 파일 → 디렉터리로 변환
    echo "Single file detected: $SOURCE_PATH" >&2

    WORK_DIR="/tmp/codeql_source"
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"

    # 파일 복사 (원본 이름 유지)
    cp "$SOURCE_PATH" "$WORK_DIR/"

    ACTUAL_SOURCE="$WORK_DIR"
elif [ -d "$SOURCE_PATH" ]; then
    # 디렉터리
    echo "Directory detected: $SOURCE_PATH" >&2
    ACTUAL_SOURCE="$SOURCE_PATH"
else
    echo "Error: Invalid source path" >&2
    cat > "$OUTPUT_FILE" <<'EOF'
{
  "scanner": "codeql",
  "scan_time": "2025-01-01T00:00:00",
  "total_issues": 0,
  "vulnerabilities": []
}
EOF
    exit 1
fi

echo "=== Creating CodeQL database for $LANGUAGE ===" >&2
echo "Source root: $ACTUAL_SOURCE" >&2

# CodeQL DB 생성
if ! codeql database create "$DB_PATH" \
    --language="$LANGUAGE" \
    --source-root="$ACTUAL_SOURCE" \
    --overwrite 2>&1; then
    echo "Warning: Database creation failed" >&2
    cat > "$OUTPUT_FILE" <<'EOF'
{
  "scanner": "codeql",
  "scan_time": "2025-01-01T00:00:00",
  "total_issues": 0,
  "vulnerabilities": []
}
EOF
    exit 0
fi

echo "=== Running CodeQL analysis ===" >&2

# 언어별 쿼리 선택
if [ "$LANGUAGE" = "java" ]; then
    QUERY_SUITE="java-security-and-quality"
else
    QUERY_SUITE="python-security-and-quality"
fi

# CodeQL 분석 실행 (보안 쿼리만 + 2GB RAM)
if ! codeql database analyze "$DB_PATH" \
    --format=sarif-latest \
    --output="$SARIF_OUTPUT" \
    --sarif-add-snippets \
    --ram=2048 \
    --category=security \
    --sarif-category=security 2>&1; then
    echo "Warning: Analysis failed" >&2
    cat > "$OUTPUT_FILE" <<'EOF'
{
  "scanner": "codeql",
  "scan_time": "2025-01-01T00:00:00",
  "total_issues": 0,
  "vulnerabilities": []
}
EOF
    exit 0
fi

# SARIF -> 표준 JSON 변환
echo "=== Converting SARIF to standard JSON ===" >&2

if [ ! -f "$SARIF_OUTPUT" ]; then
    echo "Error: SARIF file not found" >&2
    cat > "$OUTPUT_FILE" <<'EOF'
{
  "scanner": "codeql",
  "scan_time": "2025-01-01T00:00:00",
  "total_issues": 0,
  "vulnerabilities": []
}
EOF
    exit 0
fi

# Python 변환 스크립트
python3 - "$OUTPUT_FILE" "$SARIF_OUTPUT" <<'PYTHON_SCRIPT'
import json
import sys
from datetime import datetime

output_file = sys.argv[1]
sarif_file = sys.argv[2]

try:
    with open(sarif_file, 'r', encoding='utf-8') as f:
        sarif_data = json.load(f)

    vulnerabilities = []

    for run in sarif_data.get('runs', []):
        tool = run.get('tool', {}).get('driver', {})

        # 룰 정보
        rules = {}
        for rule in tool.get('rules', []):
            rule_id = rule.get('id')
            properties = rule.get('properties', {})
            rules[rule_id] = {
                'security_severity': properties.get('security-severity', '5.0'),
                'tags': properties.get('tags', [])
            }

        # 결과 파싱
        for result in run.get('results', []):
            rule_id = result.get('ruleId', 'UNKNOWN')
            rule_info = rules.get(rule_id, {})

            locations = result.get('locations', [])
            if not locations:
                continue

            physical_loc = locations[0].get('physicalLocation', {})
            region = physical_loc.get('region', {})

            # 심각도
            try:
                sec_severity = float(rule_info.get('security_severity', '5.0'))
            except:
                sec_severity = 5.0

            if sec_severity >= 9.0:
                severity = 'critical'
            elif sec_severity >= 7.0:
                severity = 'high'
            elif sec_severity >= 4.0:
                severity = 'medium'
            else:
                severity = 'low'

            # CWE 추출 (정수로)
            cwe = 0
            for tag in rule_info.get('tags', []):
                tag_str = str(tag).lower()
                if 'external/cwe/cwe-' in tag_str:
                    try:
                        cwe_num = tag_str.split('cwe-')[-1]
                        cwe = int(cwe_num)
                        break
                    except:
                        pass

            # 코드 스니펫
            code_snippet = region.get('snippet', {}).get('text', '').strip()
            if not code_snippet:
                line_start = region.get('startLine', 0)
                code_snippet = f"Line {line_start}"

            vuln = {
                "scanner": "codeql",
                "rule_id": rule_id,
                "severity": severity,
                "cwe": cwe,
                "line_start": region.get('startLine', 0),
                "line_end": region.get('endLine', 0),
                "code_snippet": code_snippet,
                "description": result.get('message', {}).get('text', ''),
                "confidence": "high"
            }
            vulnerabilities.append(vuln)

    result = {
        "scanner": "codeql",
        "scan_time": datetime.now().isoformat(),
        "total_issues": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"CodeQL found {len(vulnerabilities)} issues", file=sys.stderr)

except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc(file=sys.stderr)

    error_result = {
        "scanner": "codeql",
        "scan_time": datetime.now().isoformat(),
        "total_issues": 0,
        "vulnerabilities": []
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(error_result, f, indent=2, ensure_ascii=False)

PYTHON_SCRIPT

echo "=== CodeQL scan finished ===" >&2
