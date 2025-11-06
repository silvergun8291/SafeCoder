import sys
import os
import uuid
from pathlib import Path
from tqdm import tqdm
from typing import List

from qdrant_client import QdrantClient, models
from qdrant_client.models import Distance, VectorParams, PointStruct
from langchain.schema.document import Document
from langchain_community.document_loaders import DirectoryLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter

# Text RAG 임베딩 모델 로드
from langchain_upstage.embeddings import UpstageEmbeddings

# 로컬 설정 파일 임포트
try:
    from config_db import (
        QDRANT_URL, QDRANT_API_KEY, UPSTAGE_API_KEY,
        TEXT_COLLECTION_NAME, RULE_COLLECTION_NAME, TEXT_EMBEDDING_MODEL,
        TEXT_VECTOR_DIMENSION, TEXT_DATA_PATH
    )
except ImportError:
    print("🚨 config_db.py를 찾을 수 없거나 설정 임포트 오류.")
    sys.exit(1)


# --- 1. Qdrant 유틸리티 함수 ---

def recreate_qdrant_collection(client: QdrantClient, collection_name: str, vector_dim: int):
    """지정된 이름으로 Qdrant 컬렉션을 초기화하거나 새로 생성합니다."""
    try:
        print(f"\nQdrant 컬렉션 '{collection_name}'을 초기화합니다.")
        # 코사인 유사도 사용 (Solar 모델 표준)
        client.recreate_collection(
            collection_name=collection_name,
            vectors_config=VectorParams(size=vector_dim, distance=Distance.COSINE)
        )
        print(f"컬렉션 '{collection_name}' (차원: {vector_dim}) 준비 완료.")
        return True
    except Exception as e:
        print(f"🚨 Error: Qdrant 컬렉션 초기화 중 오류 발생. Qdrant 서버 상태 확인 필요: {e}")
        return False


def upload_batch(client: QdrantClient, collection_name: str, points: List[PointStruct]):
    """배치 단위로 Qdrant에 포인트를 업로드합니다."""
    client.upsert(
        collection_name=collection_name,
        points=points,
        wait=True
    )


# --- 2. Text RAG 데이터 로드 및 인덱싱 로직 ---

def load_and_tag_documents(path: Path, glob_pattern: str, source_type: str) -> List[Document]:
    """문서를 로드하고 메타데이터를 태그합니다."""
    target_path = TEXT_DATA_PATH / path
    if not target_path.exists():
        print(f"경고: 데이터 경로 '{target_path}'를 찾을 수 없습니다. 건너뜁니다.")
        return []

    print(f"Loading {source_type} documents from {target_path} (Glob: {glob_pattern})...")

    # PDF, HTML, MD 등 다양한 문서를 처리하기 위해 DirectoryLoader 사용
    loader = DirectoryLoader(
        str(target_path),
        glob=glob_pattern,
        show_progress=True,
        use_multithreading=True,
        silent_errors=True
    )

    documents = loader.load()

    for doc in documents:
        doc.metadata["source_type"] = source_type
        doc.metadata["language"] = "generic_text"
        doc.metadata["source"] = doc.metadata.get("source", str(target_path.name))  # 소스 파일/폴더 이름

    print(f"Loaded {len(documents)} {source_type} documents.")
    return documents


def index_documents_to_qdrant(documents: List[Document], collection_name: str, client: QdrantClient,
                              embed_model: UpstageEmbeddings):
    """문서를 분할하고 임베딩하여 지정된 Qdrant 컬렉션에 저장합니다."""

    if not documents:
        print(f"경고: {collection_name}에 저장할 문서가 없습니다. 인덱싱을 건너뜁니다.")
        return

    print(f"\n--- Text RAG Processing for Collection: {collection_name} ---")

    # 문서 분할 (청크)
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=200,
    )
    texts = text_splitter.split_documents(documents)
    print(f"Split documents into {len(texts)} chunks.")

    # 임베딩 생성 (Solar API 호출)
    print(f"Generating embeddings for {len(texts)} chunks using {TEXT_EMBEDDING_MODEL}...")
    text_list = [t.page_content for t in texts]
    vectors = embed_model.embed_documents(text_list)

    points_to_upload: List[PointStruct] = []

    for i, vector in enumerate(tqdm(vectors, desc=f"Uploading {collection_name}")):
        doc = texts[i]

        payload = doc.metadata
        payload['page_content'] = doc.page_content  # 원본 텍스트 내용을 payload에 저장

        points_to_upload.append(
            PointStruct(
                id=str(uuid.uuid4()),  # 고유 ID 생성
                vector=vector,
                payload=payload
            )
        )

    upload_batch(client, collection_name, points_to_upload)

    count = client.count(collection_name=collection_name, exact=True).count
    print(f"✅ {collection_name} 업로드 완료. 총 포인트: {count}")


# --- 3. 메인 실행 함수 ---

def main():
    print("--- Text RAG Vector DB 구축 시작 ---")

    try:
        client = QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY)
    except Exception as e:
        print(f"🚨 Qdrant 서버 연결에 실패했습니다. {QDRANT_URL}")
        print("Qdrant Docker 또는 서버가 실행 중인지 확인하세요.")
        sys.exit(1)

    # 1. 컬렉션 초기화
    recreate_qdrant_collection(client, TEXT_COLLECTION_NAME, TEXT_VECTOR_DIMENSION)
    recreate_qdrant_collection(client, RULE_COLLECTION_NAME, TEXT_VECTOR_DIMENSION)

    # 2. Text RAG 임베딩 모델 초기화
    os.environ["UPSTAGE_API_KEY"] = UPSTAGE_API_KEY
    if not UPSTAGE_API_KEY:
        print("🚨 UPSTAGE_API_KEY가 설정되지 않아 Text RAG 모델을 로드할 수 없습니다. 스크립트를 종료합니다.")
        sys.exit(1)

    embed_model = UpstageEmbeddings(model=TEXT_EMBEDDING_MODEL)
    print(f"✅ Text Embedding Model ({TEXT_EMBEDDING_MODEL}) 로드 완료.")

    # 3. Text DB 업로드 (KISA + OWASP)
    kisa_docs = load_and_tag_documents(Path("raw/text_kisa"), "*.pdf", "KISA_SecureCoding")
    owasp_docs = load_and_tag_documents(Path("raw/text_owasp"), "*.html", "OWASP_CheatSheet")
    text_db_documents = kisa_docs + owasp_docs
    index_documents_to_qdrant(text_db_documents, TEXT_COLLECTION_NAME, client, embed_model)

    # 4. Rule DB 업로드 (Semgrep Docs)
    semgrep_docs = load_and_tag_documents(Path("raw/text_semgrep"), "*.md", "Semgrep_Autofix")
    index_documents_to_qdrant(semgrep_docs, RULE_COLLECTION_NAME, client, embed_model)

    print("\n--- ✅ Text RAG Vector DB 구축 완료! (text_db, rule_db) ---")


if __name__ == "__main__":
    main()
