"""
scanner_service 통합 테스트

실행 방법:
    pytest backend/tests/test_scanner_service.py -v -s
    pytest backend/tests/test_scanner_service.py::test_scan_python_code -v -s
"""

import pytest
import asyncio
from pathlib import Path
import sys

# 프로젝트 루트를 PYTHONPATH에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.scanning.scanner_service import ScannerService
from app.models.schemas import ScanRequest, Language, ScanOptions, Severity


# ==================== 테스트용 취약한 코드 ====================

VULNERABLE_PYTHON = """
import os
import pickle
import subprocess
import tempfile

def unsafe_function(user_input):
    # B602: SQL injection
    query = "SELECT * FROM users WHERE id = " + user_input

    # B301: pickle.loads
    data = pickle.loads(user_input)

    # B605: shell injection
    os.system("ls " + user_input)

    # B608: hardcoded password
    password = "admin123"
    api_key = "sk-1234567890"

    # B603: subprocess with shell
    subprocess.call("echo " + user_input, shell=True)

    # CWE-377: Insecure temporary file (CodeQL이 찾음!)
    tmp = tempfile.mktemp()
    with open(tmp, 'w') as f:
        f.write(user_input)

    return query

# ⭐ 실제 호출 (CodeQL 데이터 흐름 분석용)
if __name__ == "__main__":
    user_data = b"malicious_data"
    result = unsafe_function(user_data)
"""

VULNERABLE_JAVA = """
import java.io.*;
import java.sql.*;

public class Vulnerable {
    // SQL Injection
    public void sqlInjection(String userInput) {
        String query = "SELECT * FROM users WHERE id = " + userInput;
    }

    // Command Injection
    public void commandInjection(String userInput) throws IOException {
        Runtime.getRuntime().exec("ls " + userInput);
    }

    // Path Traversal
    public void pathTraversal(String filename) throws IOException {
        File file = new File("/var/data/" + filename);
        FileInputStream fis = new FileInputStream(file);
    }

    // Hardcoded Password
    public void hardcodedSecret() {
        String password = "admin123";
        String apiKey = "sk-1234567890";
    }

    // Unsafe Deserialization
    public void unsafeDeserialize(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        Object obj = ois.readObject();
    }

    // ⭐ main 메서드 추가 (CodeQL 데이터 흐름 분석용)
    public static void main(String[] args) throws Exception {
        Vulnerable vc = new Vulnerable();

        // 실제 호출 (데이터 흐름 생성)
        String userInput = args.length > 0 ? args[0] : "malicious";

        vc.sqlInjection(userInput);
        vc.commandInjection(userInput);
        vc.pathTraversal("../../etc/passwd");
        vc.hardcodedSecret();

        ByteArrayInputStream bais = new ByteArrayInputStream(new byte[]{});
        vc.unsafeDeserialize(bais);
    }
}
"""

CLEAN_PYTHON = """
def safe_function(x: int, y: int) -> int:
    '''안전한 함수'''
    result = x + y
    return result

if __name__ == "__main__":
    print(safe_function(1, 2))
"""

CLEAN_JAVA = """
public class Safe {
    public int add(int a, int b) {
        return a + b;
    }
    
    public static void main(String[] args) {
        Safe safe = new Safe();
        System.out.println(safe.add(1, 2));
    }
}
"""


# ==================== Fixtures ====================

@pytest.fixture(scope="module")
def scanner_service():
    """ScannerService 인스턴스 생성 및 정리"""
    service = ScannerService()
    yield service
    service.cleanup()


@pytest.fixture(scope="module")
def event_loop():
    """이벤트 루프 생성"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ==================== Python 스캔 테스트 ====================

@pytest.mark.asyncio
async def test_scan_python_vulnerable_code(scanner_service):
    """Python 취약한 코드 스캔 테스트"""
    request = ScanRequest(
        language=Language.PYTHON,
        source_code=VULNERABLE_PYTHON,
        filename="vulnerable.py"
    )

    print("\n" + "="*70)
    print("🐍 [Python Scan] 취약한 코드 스캔 시작")
    print("="*70)

    response = await scanner_service.scan_code(request)

    # 기본 검증
    assert response.job_id is not None
    assert response.language == Language.PYTHON
    assert response.status.value in ["completed", "failed"]
    assert response.created_at is not None
    assert response.completed_at is not None
    assert response.total_execution_time > 0

    # 결과 출력
    print(f"\n📊 스캔 결과:")
    print(f"  ├─ Job ID: {response.job_id}")
    print(f"  ├─ 상태: {response.status.value}")
    print(f"  ├─ 사용 스캐너: {', '.join(response.scanners_used)}")
    print(f"  ├─ 실행 시간: {response.total_execution_time}초")
    print(f"  └─ 총 취약점: {response.total_vulnerabilities}개")

    # 심각도별 통계
    if response.severity_summary:
        print(f"\n🔍 심각도별 통계:")
        for severity, count in response.severity_summary.items():
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
                print(f"  {emoji.get(severity, '⚪')} {severity.upper()}: {count}개")

    # 스캐너별 결과
    print(f"\n📋 스캐너별 상세:")
    for result in response.results:
        status_icon = "✅" if not result.error else "❌"
        print(f"\n  {status_icon} [{result.scanner}]")
        print(f"     ├─ 발견: {result.total_issues}개")
        print(f"     ├─ 실행 시간: {result.execution_time}초")
        print(f"     └─ 종료 코드: {result.exit_code}")

        if result.error:
            print(f"        ⚠️  에러: {result.error[:60]}...")
        elif result.vulnerabilities:
            for vuln in result.vulnerabilities[:2]:  # 상위 2개만
                print(f"        • {vuln.severity.value.upper()} - {vuln.rule_id} (Line {vuln.line_start})")

    # 에러 목록
    if response.scanner_errors:
        print(f"\n⚠️  에러 목록:")
        for error in response.scanner_errors:
            print(f"  • {error}")

    # 취약점 발견 검증
    assert response.total_vulnerabilities > 0, "취약점이 발견되지 않음"
    assert len(response.aggregated_vulnerabilities) > 0

    print(f"\n✅ Python 취약 코드 스캔 테스트 통과\n")


@pytest.mark.asyncio
async def test_scan_python_clean_code(scanner_service):
    """Python 안전한 코드 스캔 테스트"""
    request = ScanRequest(
        language=Language.PYTHON,
        source_code=CLEAN_PYTHON,
        filename="safe.py"
    )

    print("\n" + "="*70)
    print("🐍 [Python Scan] 안전한 코드 스캔")
    print("="*70)

    response = await scanner_service.scan_code(request)

    print(f"\n📊 결과:")
    print(f"  ├─ 총 취약점: {response.total_vulnerabilities}개")
    print(f"  ├─ 실행 시간: {response.total_execution_time}초")
    print(f"  └─ 상태: {response.status.value}")

    assert response.total_vulnerabilities == 0, "안전한 코드에서 취약점 발견됨"
    print(f"\n✅ Python 안전 코드 스캔 테스트 통과\n")


# ==================== Java 스캔 테스트 ====================

@pytest.mark.asyncio
async def test_scan_java_vulnerable_code(scanner_service):
    """Java 취약한 코드 스캔 테스트"""
    request = ScanRequest(
        language=Language.JAVA,
        source_code=VULNERABLE_JAVA,
        filename="Vulnerable.java"
    )

    print("\n" + "="*70)
    print("☕ [Java Scan] 취약한 코드 스캔 시작")
    print("="*70)

    response = await scanner_service.scan_code(request)

    print(f"\n📊 스캔 결과:")
    print(f"  ├─ Job ID: {response.job_id}")
    print(f"  ├─ 사용 스캐너: {', '.join(response.scanners_used)}")
    print(f"  ├─ 실행 시간: {response.total_execution_time}초")
    print(f"  └─ 총 취약점: {response.total_vulnerabilities}개")

    if response.severity_summary:
        print(f"\n🔍 심각도별 통계:")
        for severity, count in response.severity_summary.items():
            if count > 0:
                print(f"  • {severity.upper()}: {count}개")

    print(f"\n📋 스캐너별 결과:")
    for result in response.results:
        status = "✅" if not result.error else "❌"
        print(f"  {status} [{result.scanner}]: {result.total_issues}개 (실행: {result.execution_time}초)")

    assert response.job_id is not None
    assert response.language == Language.JAVA

    print(f"\n✅ Java 취약 코드 스캔 테스트 통과\n")


# ==================== 옵션 테스트 ====================

@pytest.mark.asyncio
async def test_scan_with_specific_scanners(scanner_service):
    """특정 스캐너만 실행 테스트"""
    options = ScanOptions(
        specific_scanners=["bandit"],
        min_severity=Severity.MEDIUM,
        timeout=120
    )

    request = ScanRequest(
        language=Language.PYTHON,
        source_code=VULNERABLE_PYTHON,
        filename="test.py",
        options=options
    )

    print("\n" + "="*70)
    print("⚙️  [Options Test] 특정 스캐너 + 심각도 필터")
    print("="*70)

    response = await scanner_service.scan_code(request)

    print(f"\n📊 결과:")
    print(f"  ├─ 요청 스캐너: {options.specific_scanners}")
    print(f"  ├─ 실행된 스캐너: {[r.scanner for r in response.results]}")
    print(f"  ├─ 최소 심각도: {options.min_severity}")
    print(f"  └─ 총 취약점: {response.total_vulnerabilities}개")

    # Bandit만 실행되었는지 확인
    assert len(response.results) == 1
    assert response.results[0].scanner == "bandit"

    # 심각도 필터 검증
    for vuln in response.aggregated_vulnerabilities:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        assert severity_order[vuln.severity.value] <= severity_order["medium"]
        print(f"  • {vuln.severity.value.upper()} - {vuln.rule_id}")

    print(f"\n✅ 옵션 테스트 통과\n")


@pytest.mark.asyncio
async def test_scan_with_severity_filter(scanner_service):
    """심각도 필터 테스트"""
    options = ScanOptions(min_severity=Severity.HIGH)

    request = ScanRequest(
        language=Language.PYTHON,
        source_code=VULNERABLE_PYTHON,
        filename="test.py",
        options=options
    )

    print("\n" + "="*70)
    print("🔍 [Filter Test] 심각도 필터 (HIGH 이상)")
    print("="*70)

    response = await scanner_service.scan_code(request)

    print(f"\n📊 결과:")
    print(f"  ├─ 필터: HIGH 이상")
    print(f"  └─ 필터링된 취약점: {response.total_vulnerabilities}개")

    # HIGH 이상만 있는지 확인
    for vuln in response.aggregated_vulnerabilities:
        assert vuln.severity.value in ["critical", "high"]
        print(f"  • {vuln.severity.value.upper()} - {vuln.rule_id} (Line {vuln.line_start})")

    print(f"\n✅ 심각도 필터 테스트 통과\n")


# ==================== 멀티파일 테스트 ====================

@pytest.mark.asyncio
async def test_multifile_scan(scanner_service):
    """멀티파일 스캔 테스트"""
    main_code = """
from utils import process_data

def main(user_input):
    result = process_data(user_input)
    return result
"""

    utils_code = """
import os

def process_data(data):
    # 취약점: shell injection
    os.system("echo " + data)
    return data
"""

    request = ScanRequest(
        language=Language.PYTHON,
        source_code=main_code,
        filename="main.py",
        project_name="multifile_test",
        additional_files={"utils.py": utils_code}
    )

    print("\n" + "="*70)
    print("📁 [Multifile Test] 멀티파일 프로젝트 스캔")
    print("="*70)

    response = await scanner_service.scan_code(request)

    print(f"\n📊 결과:")
    print(f"  ├─ 프로젝트: multifile_test")
    print(f"  ├─ 파일 수: 2개 (main.py, utils.py)")
    print(f"  └─ 총 취약점: {response.total_vulnerabilities}개")

    # 파일별 취약점
    file_groups = {}
    for vuln in response.aggregated_vulnerabilities:
        # file_path가 비어있거나 None이면 filename 사용
        if vuln.file_path and vuln.file_path.strip():
            file = vuln.file_path
        else:
            file = f"<source_file>" if not vuln.file_path else "unknown"

        if file not in file_groups:
            file_groups[file] = []
        file_groups[file].append(vuln)

    print(f"\n📂 파일별 취약점:")
    for file_path, vulns in file_groups.items():
        print(f"  • {file_path}: {len(vulns)}개")

    assert response.total_vulnerabilities > 0
    print(f"\n✅ 멀티파일 스캔 테스트 통과\n")


# ==================== 집계 및 정렬 테스트 ====================

@pytest.mark.asyncio
async def test_vulnerability_aggregation(scanner_service):
    """취약점 집계 및 중복 제거 테스트"""
    request = ScanRequest(
        language=Language.PYTHON,
        source_code=VULNERABLE_PYTHON,
        filename="test.py"
    )

    print("\n" + "="*70)
    print("📊 [Aggregation Test] 취약점 집계 및 정렬")
    print("="*70)

    response = await scanner_service.scan_code(request)

    # 집계 통계
    total_from_scanners = sum(r.total_issues for r in response.results)

    print(f"\n📈 집계 통계:")
    print(f"  ├─ 개별 스캐너 총합: {total_from_scanners}개")
    print(f"  ├─ 중복 제거 후: {response.total_vulnerabilities}개")
    print(f"  └─ 중복 제거율: {(1 - response.total_vulnerabilities/max(total_from_scanners, 1))*100:.1f}%")

    # 중복 제거 검증
    assert response.total_vulnerabilities <= total_from_scanners

    # 정렬 검증
    severities = [v.severity.value for v in response.aggregated_vulnerabilities]
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    severity_values = [severity_order[s] for s in severities]

    print(f"\n🔢 정렬 검증:")
    for i, vuln in enumerate(response.aggregated_vulnerabilities[:5], 1):
        print(f"  {i}. {vuln.severity.value.upper():8} - {vuln.rule_id:20} (Line {vuln.line_start})")

    # 정렬 확인
    for i in range(len(severity_values) - 1):
        assert severity_values[i] <= severity_values[i + 1], "심각도 순 정렬 실패"

    print(f"\n✅ 집계 및 정렬 테스트 통과\n")


# ==================== 메인 실행 ====================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
