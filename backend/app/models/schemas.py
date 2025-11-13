from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field, ConfigDict


class Language(str, Enum):
    """지원 언어"""
    PYTHON = "python"
    JAVA = "java"


class Severity(str, Enum):
    """취약점 심각도"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanStatus(str, Enum):
    """스캔 상태"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class VulnerabilityInfo(BaseModel):
    """취약점 정보"""
    # 기본 정보
    scanner: str = Field(..., description="스캐너 이름")
    rule_id: str = Field(..., description="규칙 ID")
    severity: Severity = Field(..., description="심각도")
    cwe: int = Field(default=0, description="CWE 번호 (정수)")

    # 위치 정보
    file_path: str = Field(default="", description="파일 경로")
    line_start: int = Field(..., description="시작 라인")
    line_end: int = Field(..., description="종료 라인")
    column_start: Optional[int] = Field(None, description="시작 컬럼")
    column_end: Optional[int] = Field(None, description="종료 컬럼")

    # 상세 정보
    code_snippet: str = Field(default="", description="코드 스니펫")
    description: str = Field(..., description="취약점 설명")

    # 추가 분석 정보 (Phase 3-5용)
    recommendation: Optional[str] = Field(None, description="보안 가이드라인 권장사항")
    dataflow_info: Optional[str] = Field(None, description="CPG 데이터 흐름 정보")

    # 메타데이터
    references: List[str] = Field(default_factory=list, description="참고 링크")


class PromptTechnique(str, Enum):
    """프롬프트 엔지니어링 기법"""
    SECURITY_FOCUSED = "security_focused"
    CHAIN_OF_THOUGHT = "chain_of_thought"
    RCI = "recursive_criticism_improvement"
    COMBINED = "combined"


class SecureCodePrompt(BaseModel):
    """LLM 시큐어 코딩을 위한 고급 프롬프트"""
    system_prompt: str = Field(..., description="시스템 레벨 지시사항")
    user_prompt: str = Field(..., description="사용자 요청 프롬프트")
    vulnerabilities: List[Dict[str, Any]] = Field(..., description="취약점 목록")
    metadata: Dict[str, Any] = Field(..., description="컨텍스트 메타데이터")
    technique: PromptTechnique = Field(..., description="적용된 프롬프트 기법")


class LLMFixContext(BaseModel):
    """LLM 시큐어 코딩을 위한 컨텍스트"""
    vulnerabilities: List[Dict[str, Any]]
    language: str
    source_code: str
    total_vulnerabilities: int
    severity_distribution: Dict[str, int]


class ScannerResult(BaseModel):
    """스캐너 실행 결과"""
    scanner: str = Field(..., description="스캐너 이름")
    scanner_version: Optional[str] = Field(None, description="스캐너 버전")
    scan_time: datetime = Field(default_factory=datetime.now, description="스캔 시간")

    # 결과 정보
    total_issues: int = Field(..., description="발견된 이슈 수")
    vulnerabilities: List[VulnerabilityInfo] = Field(default_factory=list)

    # 실행 정보
    error: Optional[str] = Field(None, description="에러 메시지")
    exit_code: Optional[int] = Field(None, description="프로세스 종료 코드")
    execution_time: Optional[float] = Field(None, description="실행 시간 (초)")

    # 통계
    severity_counts: Dict[str, int] = Field(
        default_factory=dict,
        description="심각도별 개수"
    )

    model_config = ConfigDict(
        json_encoders={
            datetime: lambda v: v.isoformat()
        }
    )


class ScanOptions(BaseModel):
    """스캔 옵션"""
    enable_cpg_analysis: bool = Field(default=False, description="CPG 분석 활성화")
    specific_scanners: Optional[List[str]] = Field(None, description="특정 스캐너만 실행")
    min_severity: Severity = Field(default=Severity.LOW, description="최소 심각도 필터")
    timeout: int = Field(default=300, description="타임아웃 (초)")
    use_code_slicing: bool = Field(default=False, description="취약 함수 슬라이싱 기반 컨텍스트 사용")
    parallel_slice_fix: bool = Field(default=False, description="슬라이스별 병렬 LLM 호출 후 순차 패치 적용")
    use_rag: bool = Field(default=False, description="RAG 섹션 결합 프롬프트 사용")
    use_codeql: bool = Field(default=False, description="CodeQL 스캐너 사용 여부 (기본 비활성화)")
    scanner_concurrency: Optional[int] = Field(
        default=None,
        description="스캐너 동시 실행 개수 (None 또는 0이면 CPU 코어 기반 자동 설정)"
    )
    scanner_cpus: Optional[float] = Field(
        default=None,
        description="스캐너 컨테이너별 CPU 코어 수 제한 (예: 0.5, 1.0, 2.0). Docker nano_cpus로 적용"
    )
    scanner_mem: Optional[str] = Field(
        default=None,
        description="스캐너 컨테이너별 메모리 제한 (예: '1g', '512m')"
    )

    model_config = ConfigDict(use_enum_values=True)


class ScanRequest(BaseModel):
    """스캔 요청"""
    language: Language = Field(..., description="프로그래밍 언어")
    source_code: str = Field(..., min_length=1, description="스캔할 소스 코드")
    filename: Optional[str] = Field(None, description="파일명")

    # 옵션
    options: ScanOptions = Field(default_factory=ScanOptions)

    # 프로젝트 컨텍스트 (멀티파일 지원용)
    project_name: Optional[str] = Field(None, description="프로젝트명")
    additional_files: Optional[Dict[str, str]] = Field(
        None,
        description="추가 파일 (파일명: 소스코드)"
    )


class ScanResponse(BaseModel):
    """스캔 응답"""
    # 기본 정보
    job_id: str = Field(..., description="작업 ID")
    status: ScanStatus = Field(default=ScanStatus.COMPLETED, description="스캔 상태")
    language: Language = Field(..., description="프로그래밍 언어")

    # 타임스탬프
    created_at: datetime = Field(default_factory=datetime.now, description="생성 시간")
    completed_at: Optional[datetime] = Field(None, description="완료 시간")

    # 결과 통계
    total_vulnerabilities: int = Field(..., description="총 취약점 수")
    severity_summary: Dict[str, int] = Field(
        default_factory=dict,
        description="심각도별 개수"
    )

    # 스캐너 정보
    scanners_used: List[str] = Field(default_factory=list, description="사용된 스캐너")
    scanner_errors: List[str] = Field(default_factory=list, description="실패한 스캐너")

    # 상세 결과
    results: List[ScannerResult] = Field(default_factory=list, description="스캐너별 결과")
    aggregated_vulnerabilities: List[VulnerabilityInfo] = Field(
        default_factory=list,
        description="중복 제거된 취약점"
    )

    # 실행 시간
    total_execution_time: float = Field(..., description="전체 실행 시간 (초)")

    model_config = ConfigDict(
        json_encoders={
            datetime: lambda v: v.isoformat()
        }
    )
