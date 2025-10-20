from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from enum import Enum
from datetime import datetime


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
    enable_rag_search: bool = Field(default=False, description="RAG 검색 활성화")
    specific_scanners: Optional[List[str]] = Field(None, description="특정 스캐너만 실행")
    min_severity: Severity = Field(default=Severity.LOW, description="최소 심각도 필터")
    timeout: int = Field(default=300, description="타임아웃 (초)")

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


# ========== Phase 3-5용 추가 스키마 ==========

class RAGContext(BaseModel):
    """RAG 검색 컨텍스트 (Phase 3)"""
    vulnerability_id: str = Field(..., description="연결된 취약점 ID")
    guideline_source: str = Field(..., description="가이드라인 출처 (KISA/OWASP)")
    relevant_content: str = Field(..., description="관련 문서 내용")
    similarity_score: float = Field(..., ge=0.0, le=1.0, description="유사도 점수")
    document_id: str = Field(..., description="문서 ID")


class PatchSuggestion(BaseModel):
    """LLM 패치 제안 (Phase 4)"""
    vulnerability_id: str = Field(..., description="대상 취약점 ID")
    original_code: str = Field(..., description="원본 코드")
    patched_code: str = Field(..., description="패치된 코드")
    explanation: str = Field(..., description="패치 설명")
    references: List[str] = Field(default_factory=list, description="참고 문서")


class SemgrepAutofix(BaseModel):
    """Semgrep Autofix 룰 (Phase 5)"""
    rule_id: str = Field(..., description="룰 ID")
    pattern: str = Field(..., description="탐지 패턴")
    fix: str = Field(..., description="수정 패턴")
    message: str = Field(..., description="메시지")
    severity: Severity = Field(..., description="심각도")
    languages: List[Language] = Field(..., description="적용 언어")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="메타데이터")


class FeedbackLoopResult(BaseModel):
    """피드백 루프 결과 (Phase 5)"""
    iteration: int = Field(..., description="반복 횟수")
    syntax_valid: bool = Field(..., description="구문 유효성")
    rescan_passed: bool = Field(..., description="재스캔 통과 여부")
    test_passed: bool = Field(..., description="테스트 통과 여부")
    remaining_issues: int = Field(..., description="남은 이슈 수")
    final_code: str = Field(..., description="최종 코드")
