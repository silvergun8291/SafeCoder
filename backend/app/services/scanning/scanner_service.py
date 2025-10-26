"""스캐너 실행 및 결과 처리 서비스"""

import asyncio
import docker
import json
import time
import tempfile
import uuid
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from collections import Counter

from app.services.scanning.scanner_config import ScannerConfig
from app.models.schemas import (
    Language, ScanRequest, ScanResponse, ScannerResult,
    VulnerabilityInfo, Severity, ScanStatus, ScanOptions
)


class ScannerService:
    """스캐너 실행 서비스"""

    def __init__(self):
        """Docker 클라이언트 초기화"""
        self.docker_client = docker.from_env()
        self.config = ScannerConfig()

    async def scan_code(self, request: ScanRequest) -> ScanResponse:
        """
        소스 코드 스캔 실행

        Args:
            request: 스캔 요청 (언어, 소스 코드, 파일명, 옵션)

        Returns:
            ScanResponse: 통합 스캔 결과
        """
        job_id = str(uuid.uuid4())
        created_at = datetime.now()
        start_time = time.time()

        # 임시 디렉터리 생성
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            source_dir = temp_path / "source"
            results_dir = temp_path / "results"
            source_dir.mkdir()
            results_dir.mkdir()

            # 소스 코드를 파일로 저장
            filename = request.filename or self._get_default_filename(request.language)
            source_file = source_dir / filename
            source_file.write_text(request.source_code, encoding='utf-8')

            # 추가 파일 저장 (멀티파일 지원)
            if request.additional_files:
                for file_name, file_content in request.additional_files.items():
                    (source_dir / file_name).write_text(file_content, encoding='utf-8')

            # 언어별 스캐너 선택
            scanners = self.config.get_scanners_for_language(request.language)

            # 특정 스캐너만 실행하는 경우
            if request.options.specific_scanners:
                scanners = [
                    s for s in scanners
                    if s["name"] in request.options.specific_scanners
                ]

            # 병렬 스캔 실행
            scan_tasks = [
                self._run_scanner(scanner, source_dir, results_dir, request.options, request.language)
                for scanner in scanners
            ]

            # 모든 스캐너 실행 완료 대기
            scanner_results = await asyncio.gather(*scan_tasks, return_exceptions=True)

            # 예외 처리 및 결과 정리
            valid_results = []
            scanner_errors = []

            for i, result in enumerate(scanner_results):
                if isinstance(result, Exception):
                    scanner_name = scanners[i]["name"]
                    error_msg = f"{scanner_name}: {str(result)}"
                    print(f"[ERROR] {error_msg}")
                    scanner_errors.append(error_msg)
                elif result is not None:
                    valid_results.append(result)
                    if result.error:
                        scanner_errors.append(f"{result.scanner}: {result.error}")

            # 취약점 집계 및 필터링
            aggregated_vulns = self._aggregate_vulnerabilities(
                valid_results,
                request.options.min_severity
            )

            # 심각도별 통계
            severity_summary = self._calculate_severity_summary(aggregated_vulns)

            completed_at = datetime.now()
            total_time = time.time() - start_time

            # 스캔 상태 결정
            status = ScanStatus.COMPLETED
            if scanner_errors and not valid_results:
                status = ScanStatus.FAILED
            elif scanner_errors:
                status = ScanStatus.COMPLETED  # 일부 성공

            return ScanResponse(
                job_id=job_id,
                status=status,
                language=request.language,
                created_at=created_at,
                completed_at=completed_at,
                total_vulnerabilities=len(aggregated_vulns),
                severity_summary=severity_summary,
                scanners_used=self.config.get_scanner_names(request.language),
                scanner_errors=scanner_errors,
                results=valid_results,
                aggregated_vulnerabilities=aggregated_vulns,
                total_execution_time=round(total_time, 2)
            )


    async def _run_scanner(
            self,
            scanner_config: Dict[str, str],
            source_dir: Path,
            results_dir: Path,
            options: ScanOptions,
            language: Language
    ) -> Optional[ScannerResult]:
        """
        개별 스캐너 실행

        Args:
            scanner_config: 스캐너 설정 딕셔너리
            source_dir: 소스 코드 디렉터리
            results_dir: 결과 저장 디렉터리
            options: 스캔 옵션
            language: 스캔 코드 언어

        Returns:
            ScannerResult 또는 None
        """
        scanner_name = scanner_config["name"]
        image = scanner_config["image"]
        output_file = scanner_config["output_file"]

        # 스캐너별 타임아웃 사용 (options.timeout보다 스캐너 고유 타임아웃 우선)
        scanner_timeout = scanner_config.get("timeout", options.timeout)

        start_time = time.time()
        scan_time = datetime.now()

        try:
            # 커스텀 이미지 빌드 확인
            if image in self.config.CUSTOM_IMAGES:
                await self._ensure_image_built(scanner_config)

            # 스캐너별 커맨드 설정
            if "command" in scanner_config:
                command = scanner_config["command"]
            elif scanner_config.get("language_param"):
                lang = "python" if language == Language.PYTHON else "java"
                command = ["/source", f"/results/{output_file}", lang]
            else:
                # 기본 entrypoint 스크립트 사용
                command = ["/source", f"/results/{output_file}"]

            # Docker 컨테이너 실행
            container = self.docker_client.containers.run(
                image=image,
                command=command,
                volumes={
                    str(source_dir): {'bind': '/source', 'mode': 'rw'},
                    str(results_dir): {'bind': '/results', 'mode': 'rw'}
                },
                detach=True,
                remove=False  # 로그 확인을 위해 수동 삭제
            )

            # 컨테이너 완료 대기 (스캐너별 타임아웃 사용)
            result = container.wait(timeout=scanner_timeout)
            exit_code = result.get('StatusCode', -1)

            # 로그 가져오기
            # ⭐ 로그 가져와서 출력 (stdout과 stderr 모두)
            logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='ignore')

            # 컨테이너 삭제
            container.remove()

            # 결과 파일 읽기
            result_file = results_dir / output_file
            if not result_file.exists():
                print(f"[{scanner_name}] 결과 파일 없음: {output_file}")
                return self._create_error_result(
                    scanner_name,
                    f"결과 파일이 생성되지 않음: {logs[:200]}",
                    exit_code,
                    scan_time
                )

            with open(result_file, 'r', encoding='utf-8') as f:
                raw_result = json.load(f)

            execution_time = time.time() - start_time

            # JSON 결과를 ScannerResult로 변환
            return self._parse_scanner_result(
                raw_result,
                execution_time,
                exit_code,
                scan_time
            )

        except docker.errors.ContainerError as e:
            error_msg = f"컨테이너 실행 오류: {e}"
            print(f"[{scanner_name}] {error_msg}")
            return self._create_error_result(scanner_name, error_msg, -1, scan_time)

        except asyncio.TimeoutError:
            error_msg = f"타임아웃 ({scanner_timeout}초 초과)"
            print(f"[{scanner_name}] {error_msg}")
            return self._create_error_result(scanner_name, error_msg, -1, scan_time)

        except Exception as e:
            error_msg = f"예상치 못한 오류: {str(e)}"
            print(f"[{scanner_name}] {error_msg}")
            return self._create_error_result(scanner_name, error_msg, -1, scan_time)


    async def _ensure_image_built(self, scanner_config: Dict[str, str]):
        """커스텀 이미지가 빌드되어 있는지 확인하고 없으면 빌드"""
        image_name = scanner_config["image"]
        build_path = scanner_config.get("build_path")

        if not build_path:
            return

        try:
            # 이미지 존재 확인
            self.docker_client.images.get(image_name)
        except docker.errors.ImageNotFound:
            print(f"[{scanner_config['name']}] 이미지 빌드 중: {image_name}")
            # 동기 방식으로 빌드 (Docker API 제약)
            self.docker_client.images.build(
                path=build_path,
                tag=image_name,
                rm=True
            )
            print(f"[{scanner_config['name']}] 이미지 빌드 완료")

    @staticmethod
    def _parse_scanner_result(
            raw_result: Dict,
            execution_time: float,
            exit_code: int,
            scan_time: datetime
    ) -> ScannerResult:
        """JSON 결과를 ScannerResult 모델로 변환"""
        vulnerabilities = []

        for vuln_data in raw_result.get("vulnerabilities", []):
            try:
                # 심각도 정규화
                severity_str = vuln_data.get("severity", "medium").lower()
                if severity_str not in ["critical", "high", "medium", "low"]:
                    severity_str = "medium"

                cwe_raw = vuln_data.get("cwe", 0)
                if isinstance(cwe_raw, str):
                    # "CWE-502" → 502
                    cwe_num = cwe_raw.replace("CWE-", "").strip()
                    cwe = int(cwe_num) if cwe_num.isdigit() else 0
                elif isinstance(cwe_raw, int):
                    cwe = cwe_raw  # ⭐ 그대로 사용
                else:
                    cwe = 0

                vuln = VulnerabilityInfo(
                    scanner=vuln_data.get("scanner", "unknown"),
                    rule_id=vuln_data.get("rule_id", "UNKNOWN"),
                    severity=Severity(severity_str),
                    cwe=cwe,
                    file_path=vuln_data.get("file_path", ""),
                    line_start=vuln_data.get("line_start", 0),
                    line_end=vuln_data.get("line_end", 0),
                    column_start=vuln_data.get("column_start"),
                    column_end=vuln_data.get("column_end"),
                    code_snippet=vuln_data.get("code_snippet", ""),
                    description=vuln_data.get("description", ""),
                    references=vuln_data.get("references", [])
                )
                vulnerabilities.append(vuln)
            except Exception as e:
                print(f"취약점 파싱 오류: {e} - {vuln_data}")
                continue

        # 심각도별 개수 계산
        severity_counts = dict(Counter(v.severity.value for v in vulnerabilities))

        return ScannerResult(
            scanner=raw_result.get("scanner", "unknown"),
            scanner_version=raw_result.get("scanner_version"),
            scan_time=scan_time,
            total_issues=raw_result.get("total_issues", len(vulnerabilities)),
            vulnerabilities=vulnerabilities,
            error=None,
            exit_code=exit_code,
            execution_time=round(execution_time, 2),
            severity_counts=severity_counts
        )

    @staticmethod
    def _create_error_result(
            scanner_name: str,
            error_message: str,
            exit_code: int,
            scan_time: datetime
    ) -> ScannerResult:
        """에러 발생 시 빈 결과 생성"""
        return ScannerResult(
            scanner=scanner_name,
            scanner_version=None,
            scan_time=scan_time,
            total_issues=0,
            vulnerabilities=[],
            error=error_message,
            exit_code=exit_code,
            execution_time=0.0,
            severity_counts={}
        )

    @staticmethod
    def _aggregate_vulnerabilities(
            results: List[ScannerResult],
            min_severity: Severity
    ) -> List[VulnerabilityInfo]:
        """
        여러 스캐너 결과에서 취약점 집계 및 중복 제거

        Args:
            results: 스캐너 결과 리스트
            min_severity: 최소 심각도 필터 (Severity Enum 또는 문자열)

        Returns:
            중복 제거된 취약점 리스트 (심각도 순 정렬)
        """
        all_vulns = []
        seen = set()  # 중복 체크용 (rule_id + line_start + file_path)

        # 심각도 우선순위
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        # ⭐ 타입 안전 처리: Enum 또는 문자열 모두 지원
        if isinstance(min_severity, str):
            min_severity_value = min_severity.lower()
        else:
            min_severity_value = min_severity.value

        # ✅ 수정: min_severity_value를 사용 (기존: min_severity.value)
        min_severity_level = severity_order.get(min_severity_value, 3)

        for result in results:
            for vuln in result.vulnerabilities:
                # 최소 심각도 필터링
                vuln_severity_level = severity_order.get(vuln.severity.value, 3)

                if vuln_severity_level > min_severity_level:
                    continue

                # 중복 체크 키 생성
                key = f"{vuln.rule_id}:{vuln.line_start}:{vuln.file_path}"
                if key not in seen:
                    seen.add(key)
                    all_vulns.append(vuln)

        # 심각도 순으로 정렬
        all_vulns.sort(
            key=lambda v: (
                severity_order.get(v.severity.value, 99),
                v.file_path,
                v.line_start
            )
        )

        return all_vulns

    @staticmethod
    def _calculate_severity_summary(
            vulnerabilities: List[VulnerabilityInfo]
    ) -> Dict[str, int]:
        """심각도별 개수 계산"""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for vuln in vulnerabilities:
            severity = vuln.severity.value
            if severity in summary:
                summary[severity] += 1

        return summary

    @staticmethod
    def _get_default_filename(language: Language) -> str:
        """언어별 기본 파일명 반환"""
        return "test.py" if language == Language.PYTHON else "Test.java"

    def cleanup(self):
        """Docker 클라이언트 정리"""
        try:
            self.docker_client.close()
        except Exception as e:
            print(f"Docker 클라이언트 종료 오류: {e}")
