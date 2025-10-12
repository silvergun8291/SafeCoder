"""
스캐너 컨테이너 통합 테스트
pytest로 실행 - 자동 cleanup 포함
"""
import docker
import json
import time
import pytest
import shutil
from pathlib import Path


# 프로젝트 루트 경로
BACKEND_DIR = Path(__file__).parent.parent
SCANNER_TEST_DIR = BACKEND_DIR / "tests" / "scanner_test"
SOURCE_DIR = SCANNER_TEST_DIR / "source"
RESULTS_DIR = SCANNER_TEST_DIR / "results"


@pytest.fixture(scope="module")
def docker_client():
    """Docker 클라이언트 생성 및 정리"""
    client = docker.from_env()
    yield client

    # Teardown: Docker 리소스 정리
    print("\n=== Docker 리소스 정리 ===")
    try:
        # 사용한 이미지 목록
        images_to_remove = ["custom/bandit:latest", "custom/dlint:latest"]

        for image_name in images_to_remove:
            try:
                client.images.remove(image_name, force=True)
                print(f"✓ 이미지 삭제: {image_name}")
            except docker.errors.ImageNotFound:
                print(f"- 이미지 없음: {image_name}")
            except Exception as e:
                print(f"✗ 이미지 삭제 실패 ({image_name}): {e}")

        # Dangling 이미지 정리
        client.images.prune(filters={'dangling': True})
        print("✓ Dangling 이미지 정리 완료")

    except Exception as e:
        print(f"✗ Docker 정리 중 오류: {e}")

    client.close()


@pytest.fixture(scope="module")
def build_images(docker_client):
    """스캐너 이미지 빌드"""
    print("\n=== Docker 이미지 빌드 ===")

    # Bandit 빌드
    bandit_path = str(BACKEND_DIR / "scanners" / "bandit")
    print(f"Bandit 빌드: {bandit_path}")
    docker_client.images.build(path=bandit_path, tag="custom/bandit:latest", rm=True)

    # Dlint 빌드
    dlint_path = str(BACKEND_DIR / "scanners" / "dlint")
    print(f"Dlint 빌드: {dlint_path}")
    docker_client.images.build(path=dlint_path, tag="custom/dlint:latest", rm=True)

    yield

    print("\n=== 이미지 빌드 정리 완료 ===")


@pytest.fixture(scope="function")
def cleanup_results():
    """테스트 결과 파일 정리"""
    # Setup: 테스트 전 결과 디렉터리가 존재하는지 확인
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    yield

    # Teardown: 테스트 후 결과 파일 정리 (선택적)
    # 주석 해제하면 테스트 후 결과 파일 자동 삭제
    # for result_file in RESULTS_DIR.glob("*.json"):
    #     result_file.unlink()
    #     print(f"✓ 결과 파일 삭제: {result_file.name}")


def test_bandit_scanner(docker_client, build_images, cleanup_results):
    """Bandit 스캐너 테스트"""
    result_file = RESULTS_DIR / "bandit_result.json"

    # 기존 결과 파일 삭제
    if result_file.exists():
        result_file.unlink()

    print("\n[Bandit] 스캔 시작...")
    start_time = time.time()

    container = None
    try:
        # 컨테이너 실행
        output = docker_client.containers.run(
            image="custom/bandit:latest",
            command=["/source", "/results/bandit_result.json"],
            volumes={
                str(SOURCE_DIR): {'bind': '/source', 'mode': 'ro'},
                str(RESULTS_DIR): {'bind': '/results', 'mode': 'rw'}
            },
            remove=True,  # 자동 삭제
            stdout=True,
            stderr=True
        )

        elapsed = time.time() - start_time
        print(f"[Bandit] 실행 시간: {elapsed:.2f}초")
        print(f"[Bandit] 출력: {output.decode('utf-8')}")

        # 결과 파일 검증
        assert result_file.exists(), "Bandit 결과 파일이 생성되지 않음"

        with open(result_file, 'r', encoding='utf-8') as f:
            result = json.load(f)

        # JSON 구조 검증
        assert 'scanner' in result
        assert result['scanner'] == 'bandit'
        assert 'total_issues' in result
        assert 'vulnerabilities' in result
        assert isinstance(result['vulnerabilities'], list)

        # 취약점 발견 검증
        assert result['total_issues'] > 0, "Bandit이 취약점을 발견하지 못함"

        print(f"[Bandit] ✓ 테스트 통과: {result['total_issues']}개 취약점 발견")

        # 상위 3개 취약점 출력
        for vuln in result['vulnerabilities'][:3]:
            print(f"  - {vuln['rule_id']}: Line {vuln['line_start']} - {vuln['description'][:60]}...")

        # 타임아웃 검증 (2분 이내)
        assert elapsed < 120, f"Bandit 실행 시간 초과: {elapsed:.2f}초"

    except docker.errors.ContainerError as e:
        print(f"[Bandit] ✗ 컨테이너 실행 오류: {e}")
        raise

    finally:
        # 혹시 남은 컨테이너 정리 (remove=True로 이미 삭제되지만 안전장치)
        try:
            if container:
                container.remove(force=True)
        except:
            pass


def test_dlint_scanner(docker_client, build_images, cleanup_results):
    """Dlint 스캐너 테스트"""
    result_file = RESULTS_DIR / "dlint_result.json"

    # 기존 결과 파일 삭제
    if result_file.exists():
        result_file.unlink()

    print("\n[Dlint] 스캔 시작...")
    start_time = time.time()

    container = None
    try:
        # 컨테이너 실행
        output = docker_client.containers.run(
            image="custom/dlint:latest",
            command=["/source", "/results/dlint_result.json"],
            volumes={
                str(SOURCE_DIR): {'bind': '/source', 'mode': 'ro'},
                str(RESULTS_DIR): {'bind': '/results', 'mode': 'rw'}
            },
            remove=True,  # 자동 삭제
            stdout=True,
            stderr=True
        )

        elapsed = time.time() - start_time
        print(f"[Dlint] 실행 시간: {elapsed:.2f}초")
        print(f"[Dlint] 출력: {output.decode('utf-8')}")

        # 결과 파일 검증
        assert result_file.exists(), "Dlint 결과 파일이 생성되지 않음"

        with open(result_file, 'r', encoding='utf-8') as f:
            result = json.load(f)

        # JSON 구조 검증
        assert 'scanner' in result
        assert result['scanner'] == 'dlint'
        assert 'total_issues' in result
        assert 'vulnerabilities' in result
        assert isinstance(result['vulnerabilities'], list)

        print(f"[Dlint] ✓ 테스트 통과: {result['total_issues']}개 취약점 발견")

        # 타임아웃 검증 (2분 이내)
        assert elapsed < 120, f"Dlint 실행 시간 초과: {elapsed:.2f}초"

    except docker.errors.ContainerError as e:
        print(f"[Dlint] ✗ 컨테이너 실행 오류: {e}")
        raise

    finally:
        # 혹시 남은 컨테이너 정리
        try:
            if container:
                container.remove(force=True)
        except:
            pass


def test_empty_source(docker_client, build_images, cleanup_results):
    """빈 소스 디렉터리 테스트"""
    empty_dir = SCANNER_TEST_DIR / "empty_source"
    empty_dir.mkdir(exist_ok=True)

    result_file = RESULTS_DIR / "bandit_empty.json"

    print("\n[Empty Test] 빈 디렉터리 스캔...")

    try:
        # Bandit 실행
        docker_client.containers.run(
            image="custom/bandit:latest",
            command=["/source", "/results/bandit_empty.json"],
            volumes={
                str(empty_dir): {'bind': '/source', 'mode': 'ro'},
                str(RESULTS_DIR): {'bind': '/results', 'mode': 'rw'}
            },
            remove=True  # 자동 삭제
        )

        # 결과 검증
        assert result_file.exists()

        with open(result_file, 'r', encoding='utf-8') as f:
            result = json.load(f)

        assert result['total_issues'] == 0, "빈 디렉터리에서 취약점이 발견됨"
        print("[Empty Test] ✓ 빈 디렉터리 처리 정상")

    finally:
        # 빈 디렉터리 정리
        if empty_dir.exists():
            shutil.rmtree(empty_dir)
            print("[Empty Test] ✓ 임시 디렉터리 삭제")


@pytest.fixture(scope="session", autouse=True)
def cleanup_all(request):
    """전체 테스트 세션 종료 후 정리"""
    def final_cleanup():
        print("\n=== 최종 정리 시작 ===")

        # Docker 시스템 정리
        try:
            client = docker.from_env()

            # 중지된 컨테이너 정리
            client.containers.prune()
            print("✓ 중지된 컨테이너 정리")

            # 사용하지 않는 볼륨 정리
            client.volumes.prune()
            print("✓ 사용하지 않는 볼륨 정리")

            # Dangling 이미지 정리
            client.images.prune(filters={'dangling': True})
            print("✓ Dangling 이미지 정리")

            client.close()

        except Exception as e:
            print(f"✗ 최종 정리 중 오류: {e}")

        print("=== 최종 정리 완료 ===")

    request.addfinalizer(final_cleanup)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
