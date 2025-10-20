#!/bin/bash

set -e

if [ -z "$1" ]; then
    echo "Error: Source code path required"
    exit 1
fi

SOURCE_PATH="$1"
OUTPUT_FILE="${2:-/results/spotbugs_result.json}"

# Java 소스 코드 컴파일
COMPILE_DIR="/tmp/compiled"
mkdir -p "$COMPILE_DIR"

echo "=== Compiling Java files ==="
JAVA_FILES=$(find "$SOURCE_PATH" -name "*.java")

if [ -z "$JAVA_FILES" ]; then
    echo "Warning: No Java files found"
    cat > "$OUTPUT_FILE" <<EOF
{
  "scanner": "spotbugs",
  "scan_time": "$(date -u +%Y-%m-%dT%H:%M:%S.%6N)",
  "total_issues": 0,
  "vulnerabilities": [],
  "error": "No Java files found"
}
EOF
    exit 0
fi

if ! javac -d "$COMPILE_DIR" $JAVA_FILES 2>&1; then
    echo "Warning: Compilation failed"
    cat > "$OUTPUT_FILE" <<EOF
{
  "scanner": "spotbugs",
  "scan_time": "$(date -u +%Y-%m-%dT%H:%M:%S.%6N)",
  "total_issues": 0,
  "vulnerabilities": [],
  "error": "Compilation failed"
}
EOF
    exit 0
fi

# SpotBugs 실행 (경고 로그 숨김)
echo "=== Running SpotBugs ==="
spotbugs -textui -low -effort:max -xml:withMessages \
  -pluginList /opt/spotbugs/plugin/findsecbugs-plugin.jar \
  -output /tmp/spotbugs_raw.xml \
  "$COMPILE_DIR" 2>/dev/null || {
    echo "Warning: SpotBugs execution failed"
    cat > "$OUTPUT_FILE" <<EOF
{
  "scanner": "spotbugs",
  "scan_time": "$(date -u +%Y-%m-%dT%H:%M:%S.%6N)",
  "total_issues": 0,
  "vulnerabilities": [],
  "error": "SpotBugs execution failed"
}
EOF
    exit 0
  }

if [ ! -f /tmp/spotbugs_raw.xml ]; then
    cat > "$OUTPUT_FILE" <<EOF
{
  "scanner": "spotbugs",
  "scan_time": "$(date -u +%Y-%m-%dT%H:%M:%S.%6N)",
  "total_issues": 0,
  "vulnerabilities": []
}
EOF
    exit 0
fi

# XML을 JSON으로 변환
python3 - "$OUTPUT_FILE" <<'PYTHON_SCRIPT'
import json
import sys
from datetime import datetime
from defusedxml.ElementTree import parse

output_file = sys.argv[1]

def parse_jvm_signature(signature):
    """JVM 시그니처를 읽기 쉬운 형식으로 변환"""
    if not signature:
        return ""

    type_map = {
        'V': 'void',
        'Z': 'boolean',
        'B': 'byte',
        'C': 'char',
        'S': 'short',
        'I': 'int',
        'J': 'long',
        'F': 'float',
        'D': 'double'
    }

    parts = signature.split('(')
    if len(parts) != 2:
        return signature

    method_part = parts[0]
    param_part = parts[1].rstrip(')')

    # 파라미터 파싱
    params = []
    i = 0
    while i < len(param_part):
        if param_part[i] == 'L':
            end = param_part.find(';', i)
            if end != -1:
                class_name = param_part[i+1:end].split('/')[-1]
                params.append(class_name)
                i = end + 1
        elif param_part[i] == '[':
            i += 1
            if i < len(param_part) and param_part[i] == 'L':
                end = param_part.find(';', i)
                if end != -1:
                    class_name = param_part[i+1:end].split('/')[-1]
                    params.append(class_name + '[]')
                    i = end + 1
            elif i < len(param_part):
                params.append(type_map.get(param_part[i], param_part[i]) + '[]')
                i += 1
        else:
            params.append(type_map.get(param_part[i], param_part[i]))
            i += 1

    # 클래스.메서드 분리
    if '.' in method_part:
        parts = method_part.rsplit('.', 1)
        class_name = parts[0]
        method_name = parts[1]
        param_str = ', '.join(params)
        return f"{class_name}.{method_name}({param_str})"
    else:
        param_str = ', '.join(params)
        return f"{method_part}({param_str})"

try:
    tree = parse('/tmp/spotbugs_raw.xml')
    root = tree.getroot()

    vulnerabilities = []

    for bug_instance in root.findall('.//BugInstance'):
        category = bug_instance.get('category', '')

        # 보안 취약점만 필터링
        if category != 'SECURITY':
            continue

        type_code = bug_instance.get('type', '')
        priority = bug_instance.get('priority', '1')

        # 심각도 매핑
        severity_map = {'1': 'HIGH', '2': 'MEDIUM', '3': 'LOW'}
        severity = severity_map.get(priority, 'INFO')

        # Class의 SourceLine (파일 경로용)
        class_elem = bug_instance.find('.//Class')
        class_source_line = class_elem.find('./SourceLine') if class_elem is not None else None
        file_path = class_source_line.get('sourcepath', '') if class_source_line is not None else ''
        line_start = int(class_source_line.get('start', '0')) if class_source_line is not None else 0
        line_end = int(class_source_line.get('end', '0')) if class_source_line is not None else 0

        # LongMessage 또는 ShortMessage
        long_msg = bug_instance.find('.//LongMessage')
        short_msg = bug_instance.find('.//ShortMessage')

        if long_msg is not None and long_msg.text:
            description = long_msg.text.strip()
        elif short_msg is not None and short_msg.text:
            description = short_msg.text.strip()
        else:
            description = type_code

        # 메서드 시그니처 (사람이 읽기 쉽게)
        method_elem = bug_instance.find('.//Method')
        code_snippet = ''

        if method_elem is not None:
            class_name = method_elem.get('classname', '')
            method_name = method_elem.get('name', '')
            signature = method_elem.get('signature', '')
            full_sig = f"{class_name}.{method_name}{signature}"
            code_snippet = parse_jvm_signature(full_sig)

        vulnerabilities.append({
            'scanner': 'spotbugs',
            'rule_id': type_code,
            'category': category,
            'severity': severity,
            'confidence': 'HIGH',
            'description': description,
            'file_path': file_path,
            'line_start': line_start,
            'line_end': line_end,
            'code_snippet': code_snippet
        })

    result = {
        'scanner': 'spotbugs',
        'scan_time': datetime.utcnow().isoformat(),
        'total_issues': len(vulnerabilities),
        'vulnerabilities': vulnerabilities
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"SpotBugs: {len(vulnerabilities)} security issues found")

except Exception as e:
    print(f"Error: {e}")
    result = {
        'scanner': 'spotbugs',
        'scan_time': datetime.utcnow().isoformat(),
        'total_issues': 0,
        'vulnerabilities': [],
        'error': str(e)
    }
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

PYTHON_SCRIPT

echo "SpotBugs scan completed"
