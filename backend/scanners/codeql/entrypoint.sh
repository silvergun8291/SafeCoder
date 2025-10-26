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

# 이전 결과 정리
rm -rf "$DB_PATH" "$SARIF_OUTPUT"

echo "=== CodeQL Version ===" >&2
codeql version >&2

echo "=== Preparing CodeQL source ===" >&2

# 단일 파일 처리
if [ -f "$SOURCE_PATH" ]; then
    echo "Single file detected: $SOURCE_PATH" >&2
    WORK_DIR="/tmp/codeql_source"
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"
    cp "$SOURCE_PATH" "$WORK_DIR/"
    ACTUAL_SOURCE="$WORK_DIR"
elif [ -d "$SOURCE_PATH" ]; then
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

# Java는 build-mode=none 사용 (CodeQL 2.16.5+)
if [ "$LANGUAGE" = "java" ]; then
    echo "Using build-mode=none for Java (no compilation required)" >&2

    codeql database create "$DB_PATH" \
        --language=java \
        --source-root="$ACTUAL_SOURCE" \
        --build-mode=none \
        --overwrite 2>&1 || {
        echo "Error: Database creation failed" >&2
        cat > "$OUTPUT_FILE" <<'EOF'
{
  "scanner": "codeql",
  "scan_time": "2025-01-01T00:00:00",
  "total_issues": 0,
  "vulnerabilities": []
}
EOF
        exit 1
    }
else
    # Python은 interpreter 언어라 빌드 불필요
    codeql database create "$DB_PATH" \
        --language="$LANGUAGE" \
        --source-root="$ACTUAL_SOURCE" \
        --overwrite 2>&1 || {
        echo "Error: Database creation failed" >&2
        cat > "$OUTPUT_FILE" <<'EOF'
{
  "scanner": "codeql",
  "scan_time": "2025-01-01T00:00:00",
  "total_issues": 0,
  "vulnerabilities": []
}
EOF
        exit 1
    }
fi

echo "=== Analyzing database ===" >&2

# 언어별 보안 쿼리 선택
if [ "$LANGUAGE" = "java" ]; then
    QUERY_SUITE="java-security-extended.qls"
else
    QUERY_SUITE="python-security-extended.qls"
fi

codeql database analyze "$DB_PATH" \
    "$QUERY_SUITE" \
    --format=sarif-latest \
    --output="$SARIF_OUTPUT" \
    --ram=2048 \
    --threads=0 2>&1 || {
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
}

# SARIF 파일 확인
if [ ! -f "$SARIF_OUTPUT" ]; then
    echo "Error: SARIF output not found" >&2
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

echo "=== Converting SARIF to JSON ===" >&2

# SARIF → JSON 변환
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

    # SARIF 구조: runs[0].results[]
    runs = sarif_data.get('runs', [])
    if not runs:
        print("Warning: No runs in SARIF", file=sys.stderr)
        raise ValueError("No runs in SARIF")

    results = runs[0].get('results', [])
    print(f"Found {len(results)} results in SARIF", file=sys.stderr)

    for result in results:
        rule_id = result.get('ruleId', 'unknown')
        message = result.get('message', {}).get('text', '')

        # 위치 정보
        locations = result.get('locations', [])
        if locations:
            physical_location = locations[0].get('physicalLocation', {})
            artifact_location = physical_location.get('artifactLocation', {})
            region = physical_location.get('region', {})

            file_path = artifact_location.get('uri', '')
            line_start = region.get('startLine', 0)
            line_end = region.get('endLine', line_start)
        else:
            file_path = ''
            line_start = 0
            line_end = 0

        # 심각도 매핑
        level = result.get('level', 'warning')
        severity_map = {
            'error': 'high',
            'warning': 'medium',
            'note': 'low'
        }
        severity = severity_map.get(level, 'medium')

        # CWE 추출 (properties에서)
        properties = result.get('properties', {})
        cwe = ''
        tags = properties.get('tags', [])
        for tag in tags:
            if tag.startswith('external/cwe/cwe-'):
                cwe = tag.replace('external/cwe/cwe-', 'CWE-').upper()
                break

        vuln = {
            "scanner": "codeql",
            "rule_id": rule_id,
            "severity": severity,
            "cwe": cwe,
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "code_snippet": "",
            "description": message
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

    print(f"✅ CodeQL: Successfully parsed {len(vulnerabilities)} issues", file=sys.stderr)

except Exception as e:
    print(f"❌ Error converting SARIF: {e}", file=sys.stderr)
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

echo "=== CodeQL analysis completed ===" >&2
