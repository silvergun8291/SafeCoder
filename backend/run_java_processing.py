import json
import asyncio
import sys
import os
import traceback  # 오류 추적을 위해 추가
from typing import List

# --- 프로젝트 모듈 임포트 설정 ---
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

try:
    from app.services.scanning.scanner_service import ScannerService
    from app.models.schemas import Language, ScanRequest, ScanOptions, ScanResponse
except ImportError as e:
    print(f"오류: 필요한 모듈을 임포트할 수 없습니다. {e}", file=sys.stderr)
    print("이 스크립트는 'scanner_service.py'가 포함된 프로젝트의 루트 디렉터리에서 실행해야 합니다.", file=sys.stderr)
    print("프로젝트에 필요한 가상 환경(venv)이 활성화되었는지 확인하세요.", file=sys.stderr)
    sys.exit(1)


async def run_scan(scanner_service: ScannerService, code: str, scanner_name: str) -> ScanResponse:
    """
    지정된 스캐너로 코드를 스캔하는 헬퍼 함수입니다.
    """
    print(f"\n--- [DEBUG] run_scan: '{scanner_name}' 스캐너 호출 ---")

    options = ScanOptions(specific_scanners=[scanner_name])
    request = ScanRequest(
        language=Language.JAVA,
        source_code=code,
        options=options
        # filename= "Debug.java" # 필요시 파일명 지정
    )

    # print(f"--- [DEBUG] ScanRequest 객체: {request.dict()}") # Pydantic v1 기준
    print(f"--- [DEBUG] ScanRequest 객체 (일부): language={request.language}, scanners={request.options.specific_scanners}")

    response = await scanner_service.scan_code(request)

    print(f"--- [DEBUG] run_scan: '{scanner_name}' 응답 완료 ---")
    print(f"--- [DEBUG] ScanResponse (요약):")
    print(f"    - Job ID: {response.job_id}")
    print(f"    - 상태: {response.status}")
    print(f"    - 총 취약점: {response.total_vulnerabilities}")
    print(f"    - 스캐너 오류: {response.scanner_errors}")
    print(f"    - 집계된 취약점 (개수): {len(response.aggregated_vulnerabilities)}")

    # 발견된 취약점 상세 출력 (최대 3개)
    if response.aggregated_vulnerabilities:
        print("    - [발견된 취약점 (최대 3개)]:")
        for i, vuln in enumerate(response.aggregated_vulnerabilities[:3]):
            print(f"        {i + 1}. {vuln.description[:100]}... (Rule: {vuln.rule_id}, Line: {vuln.line_start})")

    return response


async def process_dataset(scanner_service: ScannerService, input_file: str, output_file: str):
    """
    java.json 데이터셋을 로드하고, 스캔 로직을 적용한 뒤,
    새로운 json 파일로 저장합니다. (디버그 로그 강화)
    """
    print(f"'{input_file}' 파일 처리를 시작합니다...")

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"--- [DEBUG] '{input_file}' 로드 성공. 총 {len(data)}개 항목.")
    except FileNotFoundError:
        print(f"오류: 입력 파일 '{input_file}'을(를) 찾을 수 없습니다.", file=sys.stderr)
        return
    except json.JSONDecodeError:
        print(f"오류: '{input_file}' 파일의 JSON 형식이 올바르지 않습니다.", file=sys.stderr)
        return

    processed_data = []
    total_items = len(data)

    for i, item in enumerate(data):
        print(f"\n{'=' * 50}\n[{i + 1}/{total_items}] 항목 처리 시작...\n{'=' * 50}")

        # 1. 'patched_code' -> 'safe_code' 필드명 변경
        if 'patched_code' in item:
            item['safe_code'] = item.pop('patched_code')
            print("--- [DEBUG] 'patched_code'를 'safe_code'로 변경했습니다.")

        vulnerable_code = item.get('vulnerable_code')

        if not vulnerable_code:
            print("--- [DEBUG] 'vulnerable_code' 필드가 비어있거나 없습니다. 스캔을 건너뜁니다.")
            processed_data.append(item)
            continue

        # --- [DEBUG] 스캔할 코드 일부 출력 ---
        print(f"--- [DEBUG] 스캔 대상 'vulnerable_code' (앞 300자):")
        print(f"{vulnerable_code[:300].strip()}")
        print("--- [DEBUG] (코드 끝) ---")

        vulnerability_description = None

        # 2. Semgrep 1차 스캔
        print(f"\n--- [1] Semgrep 1차 스캔 시작...")
        try:
            semgrep_response = await run_scan(scanner_service, vulnerable_code, "semgrep")

            # 3. 취약점 발견 시 'vulnerability_description' 필드 추가
            if semgrep_response.aggregated_vulnerabilities:
                vulnerability_description = semgrep_response.aggregated_vulnerabilities[0].description
                print(f"--- [1] Semgrep: ✅ 취약점 발견!")
            else:
                print(f"--- [1] Semgrep: ❌ 취약점 미발견.")
                if semgrep_response.scanner_errors:
                    print(f"--- [1] Semgrep: (참고) 스캔 오류 발생: {semgrep_response.scanner_errors}")


        except Exception as e:
            print(f"--- [!] Semgrep 스캔 중 치명적 오류 발생: {e}", file=sys.stderr)
            traceback.print_exc()  # 오류 상세 내용 출력

        # 4. Semgrep 미발견 시 Horusec 2차 스캔
        if not vulnerability_description:
            print(f"\n--- [2] Horusec 2차 스캔 시작...")
            try:
                horusec_response = await run_scan(scanner_service, vulnerable_code, "horusec")

                # 5. 취약점 발견 시 'vulnerability_description' 필드 추가
                if horusec_response.aggregated_vulnerabilities:
                    vulnerability_description = horusec_response.aggregated_vulnerabilities[0].description
                    print(f"--- [2] Horusec: ✅ 취약점 발견!")
                else:
                    print(f"--- [2] Horusec: ❌ 취약점 미발견.")
                    if horusec_response.scanner_errors:
                        print(f"--- [2] Horusec: (참고) 스캔 오류 발생: {horusec_response.scanner_errors}")

            except Exception as e:
                print(f"--- [!] Horusec 스캔 중 치명적 오류 발생: {e}", file=sys.stderr)
                traceback.print_exc()

        # 최종 결과 정리
        if vulnerability_description:
            item['vulnerability_description'] = vulnerability_description
            print(f"\n--- [최종 결과] 'vulnerability_description' 추가됨: {vulnerability_description[:50]}...")
        else:
            print("\n--- [최종 결과] 발견된 취약점 없음.")

        processed_data.append(item)

    # 6. 최종 결과를 새 JSON 파일로 저장
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(processed_data, f, indent=4, ensure_ascii=False)
        print(f"\n{'=' * 50}\n✅ 처리 완료! 결과가 '{output_file}' 파일에 저장되었습니다.\n{'=' * 50}")
    except IOError as e:
        print(f"오류: '{output_file}' 파일 쓰기 중 오류 발생: {e}", file=sys.stderr)


async def main():
    """
    ScannerService를 초기화하고 데이터셋 처리 프로세스를 실행합니다.
    """
    scanner_service = None
    try:
        print("--- [DEBUG] ScannerService 초기화 시도...")
        scanner_service = ScannerService()
        print("--- [DEBUG] ScannerService 초기화 완료.")

        input_file = "java.json"
        output_file = "java_processed_debug.json"  # <-- 결과 파일명 변경 (원본 보존)

        print(f"--- [DEBUG] 입력: {input_file}, 출력: {output_file}")

        await process_dataset(scanner_service, input_file, output_file)

    except Exception as e:
        print(f"\n[치명적 오류] main 함수 실행 중 오류 발생: {e}", file=sys.stderr)
        traceback.print_exc()
        # Docker 데몬 연결 오류는 여기서 잡힐 가능성이 높음
        if "Connection refused" in str(e) or "Docker" in str(e):
            print("\n[!] Docker 데몬이 실행 중인지 확인하세요.", file=sys.stderr)

    finally:
        if scanner_service:
            print("\n--- [DEBUG] ScannerService 리소스 정리 시작...")
            scanner_service.cleanup()
            print("--- [DEBUG] ScannerService 리소스 정리 완료.")


# --- 스크립트 실행 ---
if __name__ == "__main__":
    try:
        import docker
    except ImportError:
        print("오류: 'docker' 라이브러리가 필요합니다. 'pip install docker'로 설치하세요.", file=sys.stderr)
        sys.exit(1)

    print("Java 데이터셋 처리 스크립트 (디버그 모드)를 시작합니다...")
    asyncio.run(main())