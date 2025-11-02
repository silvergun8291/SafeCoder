from pydantic import BaseModel, Field
from typing import List, Optional

# --- 1. API 요청 모델: 취약점 스캔 결과 (입력) ---
class ScanResultRequest(BaseModel):
    code_snippet: str = Field(..., description="취약점이 발견된 코드 조각")
    cwe_id: str = Field(..., description="코드 스캔 도구에서 감지한 CWE ID (예: CWE-89)")
    language: str = Field(..., description="코드 언어 (예: java, python)")
    description: str = Field(..., description="스캔 도구에서 제공하는 취약점 설명")
    top_k: int = Field(default=3, description="검색할 상위 문서 개수", ge=1, le=10)


# --- 2. RAG 검색 결과 모델 (Qdrant Payload) ---
class SearchResultPayload(BaseModel):
    cwe_id: str
    description: str = Field(..., description="취약점 요약 설명")
    safe_code: str = Field(..., description="취약점을 해결한 안전한 코드 예시")
    vulnerable_code: str = Field(..., description="취약점을 포함하는 코드 예시")
    abstract_vulnerable_code: Optional[str] = None
    source_file: str

class RetrievalResult(BaseModel):
    score: float = Field(..., description="벡터 유사도 점수")
    payload: SearchResultPayload

# --- 3. API 응답 모델 (순수 검색 결과만 반환) ---
class RetrievalOnlyResponse(BaseModel):
    retrieved_documents: List[RetrievalResult] = Field(..., description="입력된 취약점과 가장 유사한 취약/안전 코드 케이스 목록")