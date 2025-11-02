"""
Scanning API endpoint tests (FIXED)
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from app.models.schemas import ScanResponse, VulnerabilityInfo, Language


# ==================== FIXTURES ====================

@pytest.fixture
def client():
    """FastAPI 테스트 클라이언트"""
    return TestClient(app)


@pytest.fixture
def mock_scan_response():
    """Mock ScanResponse 객체 - 실제 스키마에 맞게 수정"""
    return ScanResponse(
        job_id="test-job-123",
        language=Language.PYTHON,  # ✅ 추가: 필수 필드
        status="completed",
        total_vulnerabilities=3,
        aggregated_vulnerabilities=[
            VulnerabilityInfo(
                scanner="bandit",
                rule_id="B608",
                severity="high",
                description="SQL injection 취약점이 발견되었습니다",
                file_path="test.py",
                line_start=10,
                line_end=10,
                code_snippet="execute(query)",
                cwe=89
            ),
            VulnerabilityInfo(
                scanner="semgrep",
                rule_id="python.lang.security.audit.dangerous-system-call",
                severity="medium",
                description="위험한 시스템 호출이 발견되었습니다",
                file_path="test.py",
                line_start=15,
                line_end=15,
                code_snippet="os.system(cmd)",
                cwe=78
            ),
            VulnerabilityInfo(
                scanner="dlint",
                rule_id="DUO138",
                severity="low",
                description="잠재적 보안 이슈가 발견되었습니다",
                file_path="test.py",
                line_start=20,
                line_end=20,
                code_snippet="eval(code)",
                cwe=95
            )
        ],
        total_execution_time=5.23
    )


# ==================== BASIC TESTS ====================

def test_scan_endpoint_exists(client):
    """스캔 엔드포인트 존재 확인"""
    response = client.post("/api/secure-coding")
    assert response.status_code in [400, 422]


def test_scan_with_empty_body(client):
    """빈 요청 바디 테스트"""
    response = client.post("/api/secure-coding", json={})
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data


# ==================== PYTHON SCAN TESTS ====================

@pytest.mark.asyncio
async def test_scan_python_code_success(client, mock_scan_response):
    """Python 코드 스캔 성공 테스트"""

    with patch('app.services.scanning.scanner_service.ScannerService.scan_code') as mock_scan:
        mock_scan.return_value = mock_scan_response

        response = client.post(
            "/api/secure-coding",
            json={
                "language": "python",
                "source_code": "import os\nos.system('ls')",
                "filename": "test.py"
            }
        )

        assert response.status_code == 200
        data = response.json()

        assert "job_id" in data
        assert "status" in data
        assert "total_vulnerabilities" in data
        assert "aggregated_vulnerabilities" in data
        assert data["total_vulnerabilities"] == 3


def test_scan_python_with_sql_injection(client):
    """SQL Injection 취약점 테스트"""

    vulnerable_code = """
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
"""

    with patch('app.services.scanning.scanner_service.ScannerService.scan_code') as mock_scan:
        mock_response = ScanResponse(
            job_id="sql-test",
            language=Language.PYTHON,  # ✅ 추가
            status="completed",
            total_vulnerabilities=1,
            aggregated_vulnerabilities=[
                VulnerabilityInfo(
                    scanner="bandit",
                    rule_id="B608",
                    severity="high",
                    description="SQL injection vulnerability detected",
                    file_path="test.py",
                    line_start=7,
                    line_end=7,
                    code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
                    cwe=89
                )
            ],
            total_execution_time=2.5
        )
        mock_scan.return_value = mock_response

        response = client.post(
            "/api/secure-coding",
            json={
                "language": "python",
                "source_code": vulnerable_code,
                "filename": "vulnerable.py"
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total_vulnerabilities"] >= 1


# ==================== JAVA SCAN TESTS ====================

@pytest.mark.asyncio
async def test_scan_java_code_success(client):
    """Java 코드 스캔 성공 테스트"""

    java_code = """
public class Example {
    public void vulnerableMethod(String input) {
        Runtime.getRuntime().exec(input);
    }
}
"""

    with patch('app.services.scanning.scanner_service.ScannerService.scan_code') as mock_scan:
        mock_response = ScanResponse(
            job_id="java-test",
            language=Language.JAVA,  # ✅ 추가
            status="completed",
            total_vulnerabilities=1,
            aggregated_vulnerabilities=[
                VulnerabilityInfo(
                    scanner="spotbugs",
                    rule_id="COMMAND_INJECTION",
                    severity="high",
                    description="Command injection detected",
                    file_path="Example.java",
                    line_start=3,
                    line_end=3,
                    code_snippet="Runtime.getRuntime().exec(input);",
                    cwe=78
                )
            ],
            total_execution_time=8.5
        )
        mock_scan.return_value = mock_response

        response = client.post(
            "/api/secure-coding",
            json={
                "language": "java",
                "source_code": java_code,
                "filename": "Example.java"
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total_vulnerabilities"] >= 1


# ==================== VALIDATION TESTS ====================

def test_scan_with_invalid_language(client):
    """지원하지 않는 언어 테스트"""
    response = client.post(
        "/api/secure-coding",
        json={
            "language": "rust",
            "source_code": "fn main() {}",
            "filename": "main.rs"
        }
    )
    assert response.status_code == 422


def test_scan_with_missing_source_code(client):
    """소스 코드 누락 테스트"""
    response = client.post(
        "/api/secure-coding",
        json={
            "language": "python",
            "filename": "test.py"
        }
    )
    assert response.status_code == 422


def test_scan_with_empty_source_code(client):
    """빈 소스 코드 테스트"""
    response = client.post(
        "/api/secure-coding",
        json={
            "language": "python",
            "source_code": "",
            "filename": "test.py"
        }
    )
    assert response.status_code == 422


def test_scan_with_missing_filename(client, mock_scan_response):
    """파일명 누락 테스트 - filename은 Optional"""

    with patch('app.services.scanning.scanner_service.ScannerService.scan_code') as mock_scan:
        mock_scan.return_value = mock_scan_response

        response = client.post(
            "/api/secure-coding",
            json={
                "language": "python",
                "source_code": "print('hello')"
            }
        )

        assert response.status_code == 200


# ==================== ERROR HANDLING TESTS ====================

@pytest.mark.asyncio
async def test_scan_with_scanner_error(client):
    """스캐너 에러 발생 테스트"""

    with patch('app.services.scanning.scanner_service.ScannerService.scan_code') as mock_scan:
        mock_scan.side_effect = Exception("Scanner service error")

        response = client.post(
            "/api/secure-coding",
            json={
                "language": "python",
                "source_code": "print('test')",
                "filename": "test.py"
            }
        )

        assert response.status_code == 500


@pytest.mark.asyncio
async def test_scan_with_timeout(client):
    """스캔 타임아웃 테스트"""

    import asyncio

    with patch('app.services.scanning.scanner_service.ScannerService.scan_code') as mock_scan:
        mock_scan.side_effect = asyncio.TimeoutError()

        response = client.post(
            "/api/secure-coding",
            json={
                "language": "python",
                "source_code": "print('test')",
                "filename": "test.py"
            }
        )

        assert response.status_code == 500


@pytest.mark.asyncio
async def test_scan_with_docker_error(client):
    """Docker 에러 테스트"""

    import docker.errors

    with patch('app.services.scanning.scanner_service.ScannerService.scan_code') as mock_scan:
        mock_scan.side_effect = docker.errors.DockerException("Container not found")

        response = client.post(
            "/api/secure-coding",
            json={
                "language": "python",
                "source_code": "print('test')",
                "filename": "test.py"
            }
        )

        assert response.status_code == 500


# ==================== OPTIONS TESTS ====================

def test_scan_with_options(client, mock_scan_response):
    """스캔 옵션 테스트"""

    with patch('app.services.scanning.scanner_service.ScannerService.scan_code') as mock_scan:
        mock_scan.return_value = mock_scan_response

        response = client.post(
            "/api/secure-coding",
            json={
                "language": "python",
                "source_code": "print('test')",
                "filename": "test.py",
                "options": {
                    "min_severity": "medium",
                    "timeout": 600
                }
            }
        )

        assert response.status_code == 200


# ==================== RESPONSE SCHEMA TESTS ====================

def test_scan_response_schema(client, mock_scan_response):
    """응답 스키마 검증"""

    with patch('app.services.scanning.scanner_service.ScannerService.scan_code') as mock_scan:
        mock_scan.return_value = mock_scan_response

        response = client.post(
            "/api/secure-coding",
            json={
                "language": "python",
                "source_code": "import os",
                "filename": "test.py"
            }
        )

        assert response.status_code == 200
        data = response.json()

        required_fields = [
            "job_id", "status", "language", "total_vulnerabilities",
            "aggregated_vulnerabilities", "total_execution_time"
        ]

        for field in required_fields:
            assert field in data, f"Missing field: {field}"


def test_vulnerability_info_schema(client, mock_scan_response):
    """취약점 정보 스키마 검증"""

    with patch('app.services.scanning.scanner_service.ScannerService.scan_code') as mock_scan:
        mock_scan.return_value = mock_scan_response

        response = client.post(
            "/api/secure-coding",
            json={
                "language": "python",
                "source_code": "import os",
                "filename": "test.py"
            }
        )

        data = response.json()
        vulnerabilities = data["aggregated_vulnerabilities"]

        if vulnerabilities:
            vuln = vulnerabilities[0]
            assert "scanner" in vuln
            assert "rule_id" in vuln
            assert "severity" in vuln
            assert "description" in vuln
            assert "file_path" in vuln
            assert vuln["severity"] in ["critical", "high", "medium", "low"]


# ==================== PERFORMANCE TESTS ====================

@pytest.mark.asyncio
async def test_scan_execution_time(client, mock_scan_response):
    """스캔 실행 시간 검증"""

    with patch('app.services.scanning.scanner_service.ScannerService.scan_code') as mock_scan:
        mock_scan.return_value = mock_scan_response

        import time
        start_time = time.time()

        response = client.post(
            "/api/secure-coding",
            json={
                "language": "python",
                "source_code": "print('test')",
                "filename": "test.py"
            }
        )

        end_time = time.time()
        elapsed = end_time - start_time

        assert response.status_code == 200
        assert elapsed < 10


# ==================== INTEGRATION TESTS ====================

def test_scan_multiple_vulnerabilities(client):
    """여러 취약점 탐지 테스트"""

    vulnerable_code = """
import os

def dangerous_function(user_input):
    os.system(user_input)
    query = f"SELECT * FROM users WHERE id = {user_input}"
    with open(f"/files/{user_input}", 'r') as f:
        data = f.read()
    return data
"""

    with patch('app.services.scanning.scanner_service.ScannerService.scan_code') as mock_scan:
        mock_response = ScanResponse(
            job_id="multi-vuln-test",
            language=Language.PYTHON,  # ✅ 추가
            status="completed",
            total_vulnerabilities=3,
            aggregated_vulnerabilities=[
                VulnerabilityInfo(
                    scanner="bandit", rule_id="B605", severity="high",
                    description="Command injection detected",
                    file_path="test.py", line_start=6, line_end=6,
                    code_snippet="os.system(user_input)", cwe=78
                ),
                VulnerabilityInfo(
                    scanner="bandit", rule_id="B608", severity="high",
                    description="SQL injection detected",
                    file_path="test.py", line_start=9, line_end=9,
                    code_snippet='query = f"SELECT * FROM users WHERE id = {user_input}"', cwe=89
                ),
                VulnerabilityInfo(
                    scanner="bandit", rule_id="B108", severity="high",
                    description="Path traversal detected",
                    file_path="test.py", line_start=12, line_end=12,
                    code_snippet='with open(f"/files/{user_input}", \'r\') as f:', cwe=22
                )
            ],
            total_execution_time=4.2
        )
        mock_scan.return_value = mock_response

        response = client.post(
            "/api/secure-coding",
            json={
                "language": "python",
                "source_code": vulnerable_code,
                "filename": "dangerous.py"
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total_vulnerabilities"] >= 3
