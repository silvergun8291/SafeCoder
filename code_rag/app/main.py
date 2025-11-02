from fastapi import FastAPI, HTTPException
from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer
import os
from typing import List, AsyncIterator
from contextlib import asynccontextmanager

from .models import ScanResultRequest, RetrievalOnlyResponse, RetrievalResult, SearchResultPayload

# --- 1. 전역 설정 ---

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION_NAME = "secure_coding_knowledge_qdrant"
MODEL_NAME = "sentence-transformers/multi-qa-distilbert-cos-v1"


# --- 2. Lifespan 이벤트 핸들러 정의 ---

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """FastAPI 애플리케이션 시작 시 Qdrant 클라이언트와 임베딩 모델을 로드합니다."""
    try:
        app.state.qdrant_client = QdrantClient(url=QDRANT_URL)
        app.state.embedding_model = SentenceTransformer(MODEL_NAME)
        print("✅ Qdrant 클라이언트 및 임베딩 모델 로드 완료. (Lifespan: STARTUP)")
    except Exception as e:
        print(f"🚨 초기화 중 오류 발생: {e}")
    yield


# --- 3. FastAPI 인스턴스 생성 ---

app = FastAPI(
    title="Secure Code Retrieval API (Retrieval-Only)",
    lifespan=lifespan
)


# --- 4. 핵심 검색 로직 ---

def perform_retrieval(request: ScanResultRequest) -> RetrievalOnlyResponse:
    """스캔 결과를 기반으로 문맥을 생성하고 Qdrant에서 관련 문서를 검색합니다."""

    # 1. 쿼리 문맥 생성 (증강 검색 전략)
    augmented_query_context = (
        f"Detected Vulnerability: {request.description} (CWE-{request.cwe_id})\n"
        f"Language: {request.language}\n"
        f"Vulnerable Code Snippet:\n{request.code_snippet}"
    )

    # 2. 쿼리 임베딩
    query_vector = app.state.embedding_model.encode(
        augmented_query_context,
        normalize_embeddings=True
    ).tolist()

    # 3. Qdrant 검색 (Retrieval)
    search_result = app.state.qdrant_client.search(
        collection_name=COLLECTION_NAME,
        query_vector=query_vector,
        limit=request.top_k,
        with_payload=True
    )

    retrieved_docs: List[RetrievalResult] = []

    for hit in search_result:
        # 검색된 Payload를 Pydantic 모델로 변환
        payload = SearchResultPayload(**hit.payload)

        retrieved_docs.append(RetrievalResult(score=hit.score, payload=payload))

    # 검색된 문서 목록만 담아 반환
    return RetrievalOnlyResponse(retrieved_documents=retrieved_docs)


# --- 5. 단일 API 엔드포인트 정의 ---

@app.post("/query_code", response_model=RetrievalOnlyResponse)
def handle_secure_query_code(request: ScanResultRequest):
    """
    정적 분석 도구의 스캔 결과를 받아, 가장 유사한 취약/안전 코드 케이스 목록을 반환합니다.
    (LLM 호출 없이 순수 검색 결과만 반환)
    """
    try:
        response = perform_retrieval(request)
        return response
    except Exception as e:
        print(f"API 처리 중 오류 발생: {e}")
        raise HTTPException(status_code=500, detail="API 처리 중 서버 오류 발생 (Qdrant 또는 임베딩 확인 필요)")