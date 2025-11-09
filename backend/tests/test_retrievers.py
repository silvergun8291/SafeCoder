"""
통합 RAG 로컬 리트리버 테스트 스크립트
- Code RAG (CodeBERT) 및 Text RAG (Solar) 기능을 로컬에서 직접 호출하여 테스트합니다.
- KISA 문서를 우대하도록 점수 가중치(Score Boosting) 로직을 적용했습니다.
"""

import os
import sys
import warnings
import re
from typing import List, Optional
from pathlib import Path
from qdrant_client import QdrantClient, models
from sentence_transformers import SentenceTransformer
from langchain_upstage.embeddings import UpstageEmbeddings
from pydantic import BaseModel, Field, ConfigDict

warnings.filterwarnings('ignore', message='Api key is used with an insecure connection')

# --- 로컬 설정 임포트 ---
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    import config_db
    QDRANT_URL = config_db.QDRANT_URL
    QDRANT_API_KEY = config_db.QDRANT_API_KEY
    UPSTAGE_API_KEY = config_db.UPSTAGE_API_KEY
    CODE_COLLECTION_NAME = config_db.CODE_COLLECTION_NAME
    CODE_EMBEDDING_MODEL = config_db.CODE_EMBEDDING_MODEL
    TEXT_EMBEDDING_MODEL = config_db.TEXT_EMBEDDING_MODEL
except ImportError as e:
    print(f"🚨 config_db.py 임포트 실패: {e}")
    sys.exit(1)

os.environ["UPSTAGE_API_KEY"] = UPSTAGE_API_KEY

# ✅ 수정된 컬렉션 이름 (Code DB 이름 변경)
COLLECTIONS = {
    "kisa": "kisa_text_db",
    "owasp": "owasp_text_db",
    "semgrep": "semgrep_rule_db",
}


# ==========================================================
# 1. Pydantic 모델 정의
# ==========================================================

class SearchResultPayload(BaseModel):
    cwe_id: Optional[str] = None
    description: Optional[str] = None
    safe_code: Optional[str] = None
    vulnerable_code: Optional[str] = None
    source_type: Optional[str] = None
    page_content: Optional[str] = None
    source: Optional[str] = None
    language: Optional[str] = None
    model_config = ConfigDict(extra="allow")

class RetrievalResult(BaseModel):
    score: float
    payload: SearchResultPayload

class ScanResultRequest(BaseModel):
    cwe_id: str = Field(..., description="CWE ID (e.g., CWE-89)")
    language: str = Field(..., description="소스 코드 언어 (java, python)")
    code_snippet: str = Field(..., description="취약한 코드 스니펫")
    description: str = Field(..., description="취약점에 대한 요약 설명")
    top_k: int = Field(2, description="검색할 상위 문서 개수")

class QueryRequest(BaseModel):
    query: str = Field(..., description="자연어 질문")
    top_k: int = Field(2, description="검색할 상위 문서 개수")


# ==========================================================
# 2. KISA 텍스트 필터링 (KISA만 적용)
# ==========================================================

def is_useful_chunk(text: str) -> bool:
    """유용한 청크 판단 (KISA용만)"""
    if len(text.strip()) < 300:
        return False

    csharp_patterns = [
        r'SqlConnection', r'SqlCommand', r'EventArgs',
        r'string usrinput', r'Request\[', r'Request\.Write',
        r'AntiXss', r'Sanitizer\.Get'
    ]

    if sum(1 for p in csharp_patterns if re.search(p, text)) >= 2:
        return False

    if len(re.findall(r'\n\d+\.\s+[^\n]{5,80}', text)) >= 5:
        return False

    return True


# ==========================================================
# 3. KISA 리랭킹 (KISA만 적용)
# ==========================================================

def rerank_kisa_results(results: List[RetrievalResult], query: str) -> List[RetrievalResult]:
    """KISA 강화된 리랭킹 (KISA용만)"""
    keywords = {
        "SQL": ["PreparedStatement", "setString", "바인딩", "파라미터", "?"],
        "XSS": ["replaceAll", "필터링", "sanitiz", "encoding", "escape"],
        "파일": ["파일", "검증", "확장자", "MIME", "type"],
    }

    for result in results:
        content = result.payload.page_content.lower() if result.payload.page_content else ""

        # 1. 쿼리 매칭 가중치
        if "SQL" in query or "sql" in query:
            for kw in keywords.get("SQL", []):
                if kw.lower() in content:
                    result.score += 0.05
        elif "XSS" in query or "xss" in query:
            for kw in keywords.get("XSS", []):
                if kw.lower() in content:
                    result.score += 0.04
        else:
            for kw_group in keywords.values():
                for kw in kw_group:
                    if kw.lower() in content:
                        result.score += 0.02

        # 2. 코드 스니펫 탐지
        code_indicators = ["def ", "import ", "class ", "try:", "except:", "cursor", "PreparedStatement"]
        code_count = sum(1 for code in code_indicators if code in content)
        if code_count >= 2:
            result.score += 0.04
        if code_count >= 4:
            result.score += 0.03

        # 3. 안전한 코드 패턴
        safe_patterns = ["parameterized", "prepared", "binding", "sanitiz", "encode", "filter"]
        if any(p in content for p in safe_patterns):
            result.score += 0.02

    results.sort(key=lambda x: x.score, reverse=True)
    return results


# ==========================================================
# 4. Code Retriever 클래스
# ==========================================================

class CodeRetriever:
    """Code RAG 검색 클래스 (CodeBERT 기반)"""

    def __init__(self, qdrant_client: QdrantClient):
        self.qdrant_client = qdrant_client
        self.model = SentenceTransformer(CODE_EMBEDDING_MODEL)

    def _get_embedding(self, text: str) -> List[float]:
        return self.model.encode(text, normalize_embeddings=True, convert_to_tensor=False).tolist()

    def query(self, request: ScanResultRequest) -> List[RetrievalResult]:
        augmented_query = (
            f"Detected Vulnerability: {request.description} (CWE-{request.cwe_id})\n"
            f"Language: {request.language}\n"
            f"Vulnerable Code Snippet:\n{request.code_snippet}"
        )

        query_vector = self._get_embedding(augmented_query)

        try:
            search_result = self.qdrant_client.query_points(
                collection_name=CODE_COLLECTION_NAME,
                query=query_vector,
                limit=request.top_k,
                with_payload=True
            )
        except Exception as e:
            print(f"❌ Code DB 검색 오류: {e}")
            return []

        retrieved_docs: List[RetrievalResult] = []
        for hit in search_result.points:
            payload = SearchResultPayload.model_validate(hit.payload)
            retrieved_docs.append(RetrievalResult(score=hit.score, payload=payload))

        return retrieved_docs


# ==========================================================
# 5. Text Retriever 클래스
# ==========================================================

class TextRetriever:
    """Text RAG 검색 클래스 (Solar 기반)"""

    def __init__(self, qdrant_client: QdrantClient):
        self.qdrant_client = qdrant_client
        self.embedding_model = UpstageEmbeddings(model=TEXT_EMBEDDING_MODEL)

    def _get_embedding(self, query: str) -> List[float]:
        return self.embedding_model.embed_query(query)

    def _query_collection(self, query: str, db_type: str, top_k: int) -> List[RetrievalResult]:
        collection_name = COLLECTIONS[db_type]
        query_vector = self._get_embedding(query)

        # KISA만 리랭킹용 fetch_k 확대
        fetch_k = top_k * 3 if (db_type == "kisa") else top_k

        try:
            search_result = self.qdrant_client.query_points(
                collection_name=collection_name,
                query=query_vector,
                limit=fetch_k,
                with_payload=True
            )
        except Exception as e:
            print(f"❌ Text DB ({db_type}) 검색 오류: {e}")
            return []

        retrieved_docs: List[RetrievalResult] = []
        for hit in search_result.points:
            payload = SearchResultPayload.model_validate(hit.payload)
            retrieved_docs.append(RetrievalResult(score=hit.score, payload=payload))

        # ✅ KISA에만 리랭킹 적용
        if db_type == "kisa" and retrieved_docs:
            retrieved_docs = rerank_kisa_results(retrieved_docs, query)

        return retrieved_docs[:top_k]

    def query_kisa_java(self, request: QueryRequest) -> List[RetrievalResult]:
        """KISA Java 검색"""
        java_query = f"Java - {request.query}"
        return self._query_collection(java_query, "kisa", request.top_k)

    def query_kisa_python(self, request: QueryRequest) -> List[RetrievalResult]:
        """KISA Python 검색"""
        python_query = f"Python - {request.query}"
        return self._query_collection(python_query, "kisa", request.top_k)

    def query_owasp(self, request: QueryRequest) -> List[RetrievalResult]:
        return self._query_collection(request.query, "owasp", request.top_k)

    def query_semgrep(self, request: QueryRequest) -> List[RetrievalResult]:
        return self._query_collection(request.query, "semgrep", request.top_k)


# ==========================================================
# 6. 테스트 결과 출력
# ==========================================================

def print_results(test_name: str, db_type: str, request_obj: BaseModel, results: List[RetrievalResult], use_reranking: bool = False):
    db_display = {
        "kisa_java": "📝 KISA 시큐어코딩 (Java)",
        "kisa_python": "📝 KISA 시큐어코딩 (Python)",
        "owasp": "🛡️ OWASP 보안",
        "semgrep": "🔍 Semgrep 규칙",
        "code": "💾 코드 유사성 (CodeBERT)"
    }

    print("=" * 100)
    print(f"🧪 {test_name}")
    print(f"📊 {db_display.get(db_type, db_type)}", end="")
    if use_reranking:
        print(" | 🔄 리랭킹: 활성화")
    else:
        print()

    if isinstance(request_obj, ScanResultRequest):
        print(f"언어: {request_obj.language}, CWE: {request_obj.cwe_id}")
    elif isinstance(request_obj, QueryRequest):
        print(f"쿼리: {request_obj.query}")
    print("=" * 100)

    if not results:
        print("❌ 검색 결과 없음\n")
        return

    print(f"✅ 검색 성공! ({len(results)}개)\n")

    for i, doc in enumerate(results, 1):
        payload = doc.payload
        source = payload.source or "N/A"
        source_type = payload.source_type or "N/A"

        print(f"[{i}] 유사도: {doc.score:.4f} | {source}")
        print(f"   📌 {source_type}")

        if payload.vulnerable_code:
            print(f"   CWE: {payload.cwe_id}")
            print(f"   설명: {payload.description}")
            print(f"   코드:\n   {payload.vulnerable_code}")
        elif payload.page_content:
            print(f"   내용:\n   {payload.page_content}")
        print()


# ==========================================================
# 7. 메인 테스트 실행
# ==========================================================

def main():
    print("\n" + "=" * 100)
    print("🚀 통합 RAG 리트리버 테스트 (Code DB + 4개 Text DB)")
    print("=" * 100)
    print(f"Qdrant URL: {QDRANT_URL}")
    print(f"Code DB: {CODE_COLLECTION_NAME}\n")

    try:
        client = QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY, prefer_grpc=False)
        code_retriever = CodeRetriever(client)
        text_retriever = TextRetriever(client)
    except Exception as e:
        print(f"❌ 초기화 실패: {e}")
        return

    # --- 1. Code DB 테스트 (Java SQL Injection) ---
    print("\n" + "=" * 100)
    print("1️⃣ CODE DB 테스트")
    print("=" * 100)

    java_request = ScanResultRequest(
        cwe_id="89",
        language="java",
        code_snippet='String query = "SELECT * FROM users WHERE id = " + userId;',
        description="SQL Injection - Query built by concatenation",
        top_k=2
    )

    results = code_retriever.query(java_request)
    print_results("Code DB (Java - SQL Injection)", "code", java_request, results)

    # --- 2. Code DB 테스트 (Python SQL Injection) ---
    python_request = ScanResultRequest(
        cwe_id="89",
        language="python",
        code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
        description="SQL Injection - f-string query",
        top_k=2
    )

    results = code_retriever.query(python_request)
    print_results("Code DB (Python - SQL Injection)", "code", python_request, results)

    # --- 3. KISA Java 테스트 (리랭킹 활성화) ---
    print("\n" + "=" * 100)
    print("2️⃣ KISA 시큐어코딩 DB - JAVA 테스트")
    print("=" * 100)

    kisa_java_queries = [
        "SQL Injection 방지 방법",
        "XSS 공격 필터링 기법",
        "파일 업로드 검증"
    ]

    for query_text in kisa_java_queries:
        kisa_request = QueryRequest(query=query_text, top_k=2)
        results = text_retriever.query_kisa_java(kisa_request)
        print_results(f"KISA Java - {query_text}", "kisa_java", kisa_request, results, use_reranking=True)

    # --- 4. KISA Python 테스트 (리랭킹 활성화) ---
    print("\n" + "=" * 100)
    print("3️⃣ KISA 시큐어코딩 DB - PYTHON 테스트")
    print("=" * 100)

    kisa_python_queries = [
        "SQL Injection 방지 방법",
        "XSS 공격 필터링 기법",
        "파일 업로드 검증"
    ]

    for query_text in kisa_python_queries:
        kisa_request = QueryRequest(query=query_text, top_k=2)
        results = text_retriever.query_kisa_python(kisa_request)
        print_results(f"KISA Python - {query_text}", "kisa_python", kisa_request, results, use_reranking=True)

    # --- 5. OWASP DB 테스트 ---
    print("\n" + "=" * 100)
    print("4️⃣ OWASP 보안 DB 테스트")
    print("=" * 100)

    owasp_request = QueryRequest(query="SQL Injection 취약점 완화 전략", top_k=2)
    results = text_retriever.query_owasp(owasp_request)
    print_results("OWASP - SQL Injection 취약점 완화 전략", "owasp", owasp_request, results)

    # --- 6. Semgrep DB 테스트 ---
    print("\n" + "=" * 100)
    print("5️⃣ Semgrep 규칙 DB 테스트")
    print("=" * 100)

    semgrep_request = QueryRequest(query="hardcoded credential 탐지 규칙", top_k=2)
    results = text_retriever.query_semgrep(semgrep_request)
    print_results("Semgrep - hardcoded credential", "semgrep", semgrep_request, results)

    print("\n" + "=" * 100)
    print("✅ 모든 테스트 완료")
    print("=" * 100)


if __name__ == "__main__":
    main()
