"""스캐너 실행 및 결과 처리 서비스"""

import asyncio
import json
import os
import tempfile
import textwrap
import time
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any

import docker

from app.models.schemas import (
    Language, ScanRequest, ScanResponse, ScannerResult,
    VulnerabilityInfo, Severity, ScanStatus, ScanOptions
)
from app.models.schemas import PromptTechnique, SecureCodePrompt
from app.services.scanning.scanner_config import ScannerConfig
from app.utils.code_slicing import slice_function_with_header


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

            # CodeQL 기본 제외: specific_scanners가 명시되면 그 우선, 아니면 use_codeql=True일 때만 포함
            if request.options.specific_scanners:
                scanners = [
                    s for s in scanners
                    if s["name"] in request.options.specific_scanners
                ]
            else:
                if not request.options.use_codeql:
                    scanners = [s for s in scanners if s.get("name") != "codeql"]

            # 동시성 제한 계산
            cpu_count = os.cpu_count() or 2
            auto_conc = max(2, cpu_count - 1)
            # 스캐너 수와 비교해 과도한 동시성 방지
            max_concurrency = min(len(scanners), request.options.scanner_concurrency or auto_conc)
            sem = asyncio.Semaphore(max_concurrency if max_concurrency > 0 else len(scanners))

            async def _run_with_sem(scanner_cfg: Dict[str, str]):
                async with sem:
                    # 스캐너별 결과 디렉터리 분리
                    per_results = results_dir / scanner_cfg["name"]
                    per_results.mkdir(exist_ok=True)
                    return await self._run_scanner(scanner_cfg, source_dir, per_results, request.options, request.language)

            # 병렬 스캔 실행 (세마포어로 동시성 제어)
            scan_tasks = [
                _run_with_sem(scanner)
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

        # 스캐너별 타임아웃: 설정된 옵션 상한 적용
        scanner_timeout = scanner_config.get("timeout", options.timeout)
        if options.timeout:
            try:
                scanner_timeout = min(scanner_timeout, options.timeout)
            except Exception:
                pass

        start_time = time.time()
        scan_time = datetime.now()

        try:
            # 커스텀 이미지 빌드 확인 (블로킹 → 스레드 오프로딩)
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

            # 리소스 제한 설정
            nano_cpus = None
            if options.scanner_cpus and options.scanner_cpus > 0:
                try:
                    nano_cpus = int(float(options.scanner_cpus) * 1_000_000_000)
                except Exception:
                    nano_cpus = None

            mem_limit = options.scanner_mem if options.scanner_mem else None

            def _run_and_collect() -> Dict[str, Any]:
                container = self.docker_client.containers.run(
                    image=image,
                    command=command,
                    volumes={
                        str(source_dir): {'bind': '/source', 'mode': 'rw'},
                        str(results_dir): {'bind': '/results', 'mode': 'rw'}
                    },
                    detach=True,
                    remove=False,  # 로그 확인을 위해 수동 삭제
                    nano_cpus=nano_cpus,
                    mem_limit=mem_limit,
                )
                try:
                    result = container.wait(timeout=scanner_timeout)
                    exit_code_inner = result.get('StatusCode', -1)
                    logs_inner = container.logs(stdout=True, stderr=True).decode('utf-8', errors='ignore')
                finally:
                    try:
                        container.remove()
                    except Exception:
                        pass
                return {"exit_code": exit_code_inner, "logs": logs_inner}

            # 컨테이너 실행/대기/로그 수집을 스레드로 실행
            run_result = await asyncio.to_thread(_run_and_collect)
            exit_code = run_result.get("exit_code", -1)
            logs = run_result.get("logs", "")

            # 결과 파일 읽기 (파일 IO도 스레드로)
            result_file = results_dir / output_file
            if not result_file.exists():
                print(f"[{scanner_name}] 결과 파일 없음: {output_file}")
                return self._create_error_result(
                    scanner_name,
                    f"결과 파일이 생성되지 않음: {logs[:200]}",
                    exit_code,
                    scan_time
                )

            def _read_json(path: Path) -> Dict[str, Any]:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)

            raw_result = await asyncio.to_thread(_read_json, result_file)

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
        """커스텀 이미지가 빌드되어 있는지 확인하고 없으면 빌드 (블로킹 호출을 스레드로 오프로딩)"""
        image_name = scanner_config["image"]
        build_path = scanner_config.get("build_path")

        if not build_path:
            return

        def _get_image():
            return self.docker_client.images.get(image_name)

        try:
            await asyncio.to_thread(_get_image)
        except docker.errors.ImageNotFound:
            print(f"[{scanner_config['name']}] 이미지 빌드 중: {image_name}")

            def _build():
                self.docker_client.images.build(
                    path=build_path,
                    tag=image_name,
                    rm=True
                )

            await asyncio.to_thread(_build)
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
    def prepare_llm_fix_context(
            aggregated_vulnerabilities: List[VulnerabilityInfo],
            source_code: str,
            language: Language,
            include_recommendations: bool = True
    ) -> Dict[str, Any]:
        """LLM 시큐어 코딩을 위한 최적화된 프롬프트 컨텍스트 생성"""

        vulnerabilities_data = []

        for vuln in aggregated_vulnerabilities:
            vuln_dict = {
                "cwe": vuln.cwe,
                "severity": vuln.severity.value,
                "description": vuln.description,
                "code_snippet": vuln.code_snippet,
                "file_path": vuln.file_path,
                "line_start": vuln.line_start,
                "line_end": vuln.line_end,
            }

            # 선택적 필드 추가
            if include_recommendations and vuln.recommendation:
                vuln_dict["recommendation"] = vuln.recommendation

            if vuln.references:
                vuln_dict["references"] = vuln.references

            if vuln.dataflow_info:
                vuln_dict["dataflow_info"] = vuln.dataflow_info

            vulnerabilities_data.append(vuln_dict)

        return {
            "vulnerabilities": vulnerabilities_data,
            "language": language.value,
            "source_code": source_code,
            "total_vulnerabilities": len(vulnerabilities_data),
            "severity_distribution": {
                "critical": sum(1 for v in aggregated_vulnerabilities if v.severity.value == "critical"),
                "high": sum(1 for v in aggregated_vulnerabilities if v.severity.value == "high"),
                "medium": sum(1 for v in aggregated_vulnerabilities if v.severity.value == "medium"),
                "low": sum(1 for v in aggregated_vulnerabilities if v.severity.value == "low"),
            }
        }

    @staticmethod
    def generate_secure_code_prompt(
            aggregated_vulnerabilities: List[VulnerabilityInfo],
            source_code: str,
            language: Language,
            technique: PromptTechnique = PromptTechnique.COMBINED,
    ) -> SecureCodePrompt:
        """
        고급 프롬프트 엔지니어링 기법을 적용한 시큐어 코딩 프롬프트 생성

        Args:
            aggregated_vulnerabilities: 집계된 취약점 목록
            source_code: 원본 소스 코드
            language: 프로그래밍 언어
            technique: 적용할 프롬프트 기법

        Returns:
            SecureCodePrompt: 최적화된 프롬프트 객체
        """
        context = ScannerService.prepare_llm_fix_context(
            aggregated_vulnerabilities,
            source_code,
            language,
            include_recommendations=True
        )

        # CWE별 그룹화
        cwe_groups: Dict[int, List[Dict[str, Any]]] = {}
        for vuln in context["vulnerabilities"]:
            cwe = vuln["cwe"]
            if cwe not in cwe_groups:
                cwe_groups[cwe] = []
            cwe_groups[cwe].append(vuln)

        # 기법별 시스템 프롬프트 선택
        if technique == PromptTechnique.SECURITY_FOCUSED:
            system_prompt = ScannerService._generate_security_focused_prompt(cwe_groups)
        elif technique == PromptTechnique.CHAIN_OF_THOUGHT:
            system_prompt = ScannerService._generate_cot_prompt(cwe_groups)
        elif technique == PromptTechnique.RCI:
            system_prompt = ScannerService._generate_rci_prompt(cwe_groups)
        else:
            system_prompt = ScannerService._generate_combined_prompt(cwe_groups)

        # 사용자 프롬프트
        user_prompt = ScannerService._generate_user_prompt(
            context,
        )

        return SecureCodePrompt(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            vulnerabilities=context["vulnerabilities"],
            metadata={
                "language": language.value,
                "total_vulnerabilities": context["total_vulnerabilities"],
                "severity_distribution": context["severity_distribution"],
                "cwe_categories": list(cwe_groups.keys()),
                "technique": technique.value
            },
            technique=technique
        )

    @staticmethod
    def _generate_security_focused_prompt(cwe_groups: Dict[int, List[Dict[str, Any]]]) -> str:
        """Security-Focused Prefix 기법"""
        return f"""You are an expert secure code reviewer and developer with deep knowledge of OWASP Top 10, CWE/SANS Top 25, and secure coding best practices.

                **Primary Objective**: Generate secure code that completely eliminates the following {len(cwe_groups)} categories of vulnerabilities while maintaining functionality.
                
                **Security Requirements**:
                1. Follow OWASP Secure Coding Guidelines strictly
                2. Apply defense-in-depth principles
                3. Use parameterized queries, input validation, and output encoding
                4. Implement least privilege and fail-safe defaults
                5. Ensure no new vulnerabilities are introduced
                
                **Critical CWE Categories to Fix**:
                {ScannerService._format_cwe_summary(cwe_groups)}
                
                **Output Requirements**:
                - Provide complete, production-ready secure code
                - Add inline comments explaining security measures
                - Include error handling and edge case validation
                - Ensure backward compatibility where possible

                **Strict Non-Regression & Compliance Rules**:
                - NEVER introduce hard-coded credentials, tokens, keys, or endpoints. No placeholders like "password" or "changeme".
                - Do NOT use unsafe dynamic execution or shell invocation. Prefer safe, high-level standard APIs.
                - When invoking external executables, use absolute paths and argument arrays; do not rely on PATH lookup or join string commands.
                - Validate and allowlist all external inputs (commands, paths, parameters). Reject on mismatch.
                - Follow OWASP/CWE and strictly comply with retrieved guidelines. Priority: KISA > OWASP > Code Examples.
                - Preserve functionality; use secure defaults; add robust error handling; avoid logging sensitive data.
                - Do NOT log exception names or stack traces in production logs; log only an opaque errorId. Send details to a secure error collector.
                - Allow stack traces only in debug/development mode. Never include sensitive data in logs (tokens, keys, credentials, PII, headers, bodies).

                **Verification Checklist (must be satisfied in the final answer)**:
                - [ ] No hard-coded secrets introduced
                - [ ] No unsafe dynamic execution or shell-based calls
                - [ ] External executables use absolute paths and argument arrays (no PATH lookup)
                - [ ] Inputs validated and allowlisted
                - [ ] Secure defaults and proper error handling
                - [ ] OWASP/CWE + retrieved guidance applied"""

    @staticmethod
    def _generate_cot_prompt(cwe_groups: Dict[int, List[Dict[str, Any]]]) -> str:
        """Chain-of-Thought 기법"""
        return f"""You are an expert secure code developer. Apply systematic reasoning to fix security vulnerabilities.

                **Step-by-Step Security Analysis Framework**:
                
                Let's think step-by-step for each vulnerability:
                
                **Step 1: Identify the Vulnerability Type**
                - Analyze the CWE category and attack vector
                - Understand how the vulnerability can be exploited
                - Identify affected code sections
                
                **Step 2: Analyze the Root Cause**
                - Why does this vulnerability exist?
                - What coding pattern led to this issue?
                - What security principle was violated?
                
                **Step 3: Design the Security Fix**
                - What is the most effective mitigation?
                - Are there multiple approaches? Which is best?
                - What are the trade-offs?
                
                **Step 4: Implement the Fix**
                - Apply secure coding patterns
                - Use appropriate, safe, high-level APIs
                - Add proper validation and sanitization
                
                **Step 5: Verify No New Issues**
                - Check for introduced vulnerabilities
                - Ensure functionality is preserved
                - Validate against OWASP guidelines
                
                **Vulnerabilities to Address**:
                {ScannerService._format_cwe_summary(cwe_groups)}
                
                **Strict Non-Regression & Compliance Rules**:
                - NEVER introduce hard-coded credentials, tokens, keys, or endpoints.
                - Avoid unsafe dynamic execution; prefer safe standard APIs.
                - External executables must use absolute paths and argument arrays only; never rely on PATH or string-concatenated commands.
                - Validate and allowlist all external inputs.
                - Follow OWASP/CWE and retrieved guidance with priority KISA > OWASP > Code Examples.
                - Preserve functionality; secure defaults; robust error handling.
                - Do NOT log exception names or stack traces in production logs; log only an opaque errorId. Send details to a secure error collector.
                - Allow stack traces only in debug/development mode. Never include sensitive data in logs (tokens, keys, credentials, PII, headers, bodies).

                **Verification Checklist**:
                - [ ] No hard-coded secrets
                - [ ] No unsafe dynamic execution
                - [ ] External executables use absolute paths and argument arrays
                - [ ] Inputs validated/allowlisted
                - [ ] Secure defaults + error handling
                - [ ] Guidance applied

                For each fix, explain your reasoning at each step."""

    @staticmethod
    def _generate_rci_prompt(cwe_groups: Dict[int, List[Dict[str, Any]]]) -> str:
        """Recursive Criticism and Improvement 기법"""
        return f"""You are an expert secure code developer with self-criticism capabilities.

                **RCI Process - Execute in Multiple Rounds**:
                
                **Round 1: Initial Secure Code Generation**
                - Generate code that fixes all identified vulnerabilities
                - Apply best practices and secure coding patterns
                
                **Round 2: Self-Criticism**
                After generating the code, critically review it:
                - Are there any remaining vulnerabilities?
                - Could the fix introduce new issues?
                - Are there more robust alternatives?
                - Is the code following all OWASP guidelines?
                
                **Round 3: Improvement**
                Based on your criticism:
                - Refine the security measures
                - Add additional safeguards
                - Optimize for both security and performance
                - Enhance error handling
                
                **Vulnerabilities to Fix**:
                {ScannerService._format_cwe_summary(cwe_groups)}
                
                **Output Format**:
                1. Initial secure code
                2. Self-criticism analysis
                3. Improved final code with explanations

                **Strict Non-Regression & Compliance Rules**:
                - NEVER introduce hard-coded credentials, tokens, keys, or endpoints.
                - Avoid unsafe dynamic execution; prefer safe standard APIs.
                - External executables must use absolute paths and argument arrays only; never rely on PATH or string-concatenated commands.
                - Validate and allowlist all external inputs.
                - Follow OWASP/CWE and retrieved guidance (KISA > OWASP > Code Examples).
                - Preserve functionality; secure defaults; robust error handling.
                - Do NOT log exception names or stack traces in production logs; log only an opaque errorId. Send details to a secure error collector.
                - Allow stack traces only in debug/development mode. Never include sensitive data in logs (tokens, keys, credentials, PII, headers, bodies).

                **Verification Checklist**:
                - [ ] No hard-coded secrets
                - [ ] No unsafe dynamic execution
                - [ ] External executables use absolute paths and argument arrays
                - [ ] Inputs validated/allowlisted
                - [ ] Secure defaults + error handling
                - [ ] Guidance applied"""

    @staticmethod
    def _generate_combined_prompt(cwe_groups: Dict[int, List[Dict[str, Any]]]) -> str:
        """통합 기법 (Security-Focused + CoT + RCI)"""
        return f"""You are a world-class security engineer with expertise in OWASP, CWE, and secure software development.

                **Mission**: Transform vulnerable code into production-grade secure code following industry best practices.
                
                **Security Framework** (OWASP/CWE Compliance):
                - Apply OWASP Top 10 countermeasures
                - Follow CWE mitigation guidelines
                - Implement defense-in-depth strategy
                - Use security-by-design principles
                
                **Systematic Approach** (Chain-of-Thought):
                
                For each vulnerability, follow this process:
                1. **Identify**: Understand the CWE type and attack surface
                2. **Analyze**: Determine root cause and exploitation path
                3. **Design**: Select optimal mitigation strategy
                4. **Implement**: Apply secure coding patterns
                5. **Verify**: Ensure no new vulnerabilities introduced
                
                **Self-Review Process** (Recursive Criticism):
                
                After fixing:
                - Critique your own solution for potential weaknesses
                - Identify edge cases or bypass scenarios
                - Enhance with additional security layers
                - Validate against real-world attack patterns
                
                **Critical Vulnerabilities ({len(cwe_groups)} CWE categories)**:
                {ScannerService._format_cwe_summary(cwe_groups)}
                
                **Deliverable**:
                - Fully secure, tested code
                - Detailed security analysis
                - Inline documentation of security measures

                **Strict Non-Regression & Compliance Rules**:
                - NEVER introduce hard-coded credentials, tokens, keys, or endpoints.
                - Avoid unsafe dynamic execution; prefer safe standard APIs.
                - Validate and allowlist all external inputs.
                - Follow OWASP/CWE and retrieved guidance (KISA > OWASP > Code Examples).
                - Preserve functionality; secure defaults; robust error handling.
                - Do NOT log exception names or stack traces in production logs; log only an opaque errorId. Send details to a secure error collector.
                - Allow stack traces only in debug/development mode. Never include sensitive data in logs (tokens, keys, credentials, PII, headers, bodies).

                **Verification Checklist**:
                - [ ] No hard-coded secrets
                - [ ] No unsafe dynamic execution
                - [ ] Inputs validated/allowlisted
                - [ ] Secure defaults + error handling
                - [ ] Guidance applied"""

    @staticmethod
    def _format_cwe_summary(cwe_groups: Dict[int, List[Dict[str, Any]]]) -> str:
        """CWE 요약 포맷팅"""
        summary_lines: List[str] = []
        cwe_names = {
            89: "SQL Injection",
            78: "OS Command Injection",
            79: "Cross-Site Scripting (XSS)",
            22: "Path Traversal",
            611: "XML External Entity (XXE)",
            798: "Hard-coded Credentials",
        }

        for cwe, vulns in sorted(cwe_groups.items()):
            cwe_name = cwe_names.get(cwe, f"CWE-{cwe}")
            count = len(vulns)
            # 가장 높은 심각도를 대표로 표기
            try:
                severities = [v.get("severity", "medium") for v in vulns]
                # 우선순위: critical > high > medium > low
                order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                severity = sorted(severities, key=lambda s: order.get(str(s).lower(), 99))[0]
            except Exception:
                severity = "unknown"
            summary_lines.append(f"- CWE-{cwe} ({cwe_name}): {count} instance(s) - Severity: {str(severity).upper()}")

        return "\n".join(summary_lines)

    @staticmethod
    def _generate_user_prompt(context: Dict[str, Any]) -> str:
        """사용자 프롬프트 생성 (코드 및 취약점 상세 포함)"""
        language_str = context["language"].lower()
        language = language_str.upper()
        total = context["total_vulnerabilities"]

        prompt = textwrap.dedent(f"""# Security Vulnerability Remediation Request

                **Language**: {language}
                **Total Vulnerabilities**: {total}
                **Severity Distribution**: {context["severity_distribution"]}
                
                ## Sliced Source Context (function/method + imports/constants)
                
                """)

        # Determine Language enum
        lang_enum = Language.PYTHON if language_str == "python" else Language.JAVA

        source_code = context["source_code"]

        for idx, vuln in enumerate(context["vulnerabilities"], 1):
            # Build slice per vulnerability using line_start (fallback to 1)
            target_line = int(vuln.get("line_start") or 1)
            try:
                sliced = slice_function_with_header(lang_enum, source_code, target_line)
            except Exception:
                # Fallback: small window around line
                lines = source_code.splitlines()
                i = max(0, target_line - 1)
                start = max(0, i - 30)
                end = min(len(lines), i + 30)
                sliced = "\n".join(lines[start:end])

            prompt += textwrap.dedent(f"""### Vulnerability #{idx}
                        - **CWE**: {vuln["cwe"]}
                        - **Severity**: {str(vuln["severity"]).upper()}
                        - **Location**: {vuln["file_path"]}:{vuln["line_start"]}-{vuln["line_end"]}
                        - **Description**: {vuln["description"]}
                        
                        **Sliced Source (original)**:
                        
                        {sliced}
                        
                        **Vulnerable Code Snippet**:
                        
                        {vuln["code_snippet"]}
                        
                        """)
            if vuln.get("recommendation"):
                prompt += f"**Recommendation**: {vuln['recommendation']}\n"

            prompt += "\n"
        prompt += textwrap.dedent("""
                ## Task
                
                Generate complete, secure code that:
                1. Fixes all identified vulnerabilities without breaking functionality
                2. Uses secure APIs and safe defaults
                3. Follows language-specific best practices
                4. Includes comprehensive error handling
                5. Adds security-focused comments
                
                Provide the corrected code with detailed explanations of security improvements.

        prompt += """)
        prompt += textwrap.dedent("""
                ## Forbidden Patterns
                - Any hard-coded credentials/tokens/keys/endpoints
                - Unsafe dynamic execution or shell-based invocation
                - Relative or PATH-based invocation of external executables
                - Unvalidated/unrestricted external inputs

                ## Required Fix Principles
                - Use safe, high-level standard APIs instead of low-level execution
                - When invoking executables, use absolute paths and argument arrays only; never concatenate command strings
                - Validate and allowlist inputs; reject on mismatch
                - Externalize secrets via environment/secret manager; never literals
                - Apply secure defaults and robust error handling

                ## Output Format Requirement
                - Provide only the corrected code block(s) and a brief checklist result
                - If a required secret/config is unknown, use a secure retrieval call and add a TODO; never insert placeholders

                ## Verification Checklist
                - [ ] No hard-coded secrets introduced
                - [ ] No unsafe dynamic execution or shell-based calls
                - [ ] External executables use absolute paths and argument arrays (no PATH lookup)
                - [ ] Inputs validated and allowlisted
                - [ ] Secure defaults and proper error handling
                - [ ] OWASP/CWE + retrieved guidance applied
                """)

        return prompt

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
