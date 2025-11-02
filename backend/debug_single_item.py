import json
import asyncio
import sys
import os
import traceback
from typing import List

# --- 프로젝트 모듈 임포트 설정 ---
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

try:
    from app.services.scanning.scanner_service import ScannerService
    from app.models.schemas import Language, ScanRequest, ScanOptions, ScanResponse
except ImportError as e:
    print(f"오류: 필요한 모듈을 임포트할 수 없습니다. {e}", file=sys.stderr)
    print("이 스크립트는 'scanner_service.py'가 포함된 프로젝트의 루트 디렉터리에서 실행해야 합니다.", file=sys.stderr)
    sys.exit(1)

# --- 디버깅할 특정 코드 ---
# (따옴표 처리를 위해 """...""" 멀티라인 문자열 사용)
VULNERABLE_CODE_STRING = """
public void execute(Transaction t) throws SQLException {
    //Statement st = t.getConnection().createStatement();
    Statement st = t.getConnection().prepareStatement(query, variables);
    try {
        ResultSet rs = st.executeQuery(query);
        ResultSetMetaData metaData = rs.getMetaData();
        while (rs.next()) {
            Map map = new HashMap();
            for (int i = 0; i < metaData.getColumnCount(); i++) {
                map.put(metaData.getColumnLabel(i + 1), rs.getString(i + 1));
            }
            list.add(map);
        }
    } finally {
        st.close();
    }
}
"""


async def run_scan(scanner_service: ScannerService, code: str, scanner_name: str) -> ScanResponse:
    """
    (디버깅용) 지정된 스캐너로 코드를 스캔하는 헬퍼 함수
    """
    print(f"\n--- [DEBUG] run_scan: '{scanner_name}' 스캐너 호출 ---")

    options = ScanOptions(specific_scanners=[scanner_name])
    request = ScanRequest(
        language=Language.JAVA,
        source_code=code,
        options=options,
        filename="DebugSQLi.java"  # 스캐너가 파일을 인식하도록 이름 지정
    )

    print(f"--- [DEBUG] ScanRequest 객체 (일부): language={request.language}, scanners={request.options.specific_scanners}")

    response = await scanner_service.scan_code(request)

    print(f"--- [DEBUG] run_scan: '{scanner_name}' 응답 완료 ---")
    print(f"--- [DEBUG] ScanResponse (요약):")
    print(f"    - Job ID: {response.job_id}")
    print(f"    - 상태: {response.status}")
    print(f"    - 총 취약점 (스캐너 보고): {response.total_vulnerabilities}")
    print(f"    - 스캐너 오류: {response.scanner_errors}")
    print(f"    - 집계된 취약점 (서비스 집계): {len(response.aggregated_vulnerabilities)}")

    if response.aggregated_vulnerabilities:
        print("    - [✅ 발견된 취약점]:")
        for i, vuln in enumerate(response.aggregated_vulnerabilities):
            print(f"        {i + 1}. {vuln.description[:100]}... (Rule: {vuln.rule_id}, Line: {vuln.line_start})")
    else:
        print("    - [❌ 발견된 취약점 없음]")

    return response


async def main():
    """
    ScannerService를 초기화하고 단일 취약 코드를 스캔합니다.
    """
    scanner_service = None
    print("단일 항목 디버깅 스크립트를 시작합니다...")

    try:
        print("--- [DEBUG] ScannerService 초기화 시도...")
        scanner_service = ScannerService()
        print("--- [DEBUG] ScannerService 초기화 완료.")

        print("\n--- [TEST] 스캔할 취약 코드 (vulnerable_code): ---")
        print(VULNERABLE_CODE_STRING)
        print("-------------------------------------------------")

        # --- 1. Semgrep 스캔 ---
        print("\n--- [1] Semgrep 스캔 테스트 시작...")
        semgrep_response = await run_scan(scanner_service, VULNERABLE_CODE_STRING, "semgrep")

        # --- 2. Horusec 스캔 ---
        print("\n--- [2] Horusec 스캔 테스트 시작...")
        horusec_response = await run_scan(scanner_service, VULNERABLE_CODE_STRING, "horusec")

        print("\n" + "=" * 50)
        print("✅ 모든 테스트 완료.")
        print("=" * 50)

    except Exception as e:
        print(f"\n[치명적 오류] main 함수 실행 중 오류 발생: {e}", file=sys.stderr)
        traceback.print_exc()
        if "Docker" in str(e):
            print("\n[!] Docker 데몬이 실행 중인지 확인하세요.", file=sys.stderr)
    finally:
        if scanner_service:
            print("\n--- [DEBUG] ScannerService 리소스 정리...")
            scanner_service.cleanup()
            print("--- [DEBUG] 리소스 정리 완료.")


# --- 스크립트 실행 ---
if __name__ == "__main__":
    try:
        import docker
    except ImportError:
        print("오류: 'docker' 라이브러리가 필요합니다. 'pip install docker'로 설치하세요.", file=sys.stderr)
        sys.exit(1)

    asyncio.run(main())