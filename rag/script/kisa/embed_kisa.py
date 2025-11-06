import os
import sys
from pathlib import Path
import re
from dotenv import load_dotenv
from qdrant_client import QdrantClient, models
from qdrant_client.models import Distance, VectorParams
from langchain_upstage.embeddings import UpstageEmbeddings
from langchain.schema.document import Document
from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from tqdm import tqdm

load_dotenv()

config_dir = Path(__file__).resolve().parent.parent
if str(config_dir) not in sys.path:
    sys.path.insert(0, str(config_dir))

try:
    import config_db

    QDRANT_URL = config_db.QDRANT_URL
    QDRANT_API_KEY = config_db.QDRANT_API_KEY
    UPSTAGE_API_KEY = config_db.UPSTAGE_API_KEY
    TEXT_EMBEDDING_MODEL = config_db.TEXT_EMBEDDING_MODEL
    TEXT_VECTOR_DIMENSION = config_db.TEXT_VECTOR_DIMENSION
    KISA_DATA_PATH = config_db.KISA_DATA_PATH
except ImportError as e:
    print(f"🚨 config_db.py 임포트 실패: {e}")
    sys.exit(1)

os.environ["UPSTAGE_API_KEY"] = UPSTAGE_API_KEY
EMBEDDING_MODEL = UpstageEmbeddings(model=TEXT_EMBEDDING_MODEL)

COLLECTION_NAME = "kisa_raw_db"
CHUNK_SIZE = 2000
CHUNK_OVERLAP = 400
BATCH_SIZE = 32


def clean_pdf_text(text: str) -> str:
    """최소한의 정제만"""
    # 페이지 번호 제거
    text = re.sub(r'\n\d+\s+PART\s+\d+.*?\n', '\n', text)
    text = re.sub(r'\nPART\s+\d+.*?\n', '\n', text)

    # 줄번호 제거
    text = re.sub(r'\n\d+:\s*', '\n', text)
    text = re.sub(r'(\d+:){2,}', '', text)

    # HTML 태그 제거
    text = re.sub(r'<br\s*/?>', ' ', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)

    # 연속 공백 정리
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'\n{3,}', '\n\n', text)

    return text.strip()


def is_useful_chunk(text: str) -> bool:
    """유용한 청크인지 판단"""
    if len(text.strip()) < 200:
        return False

    numbered_lines = len(re.findall(r'\n\d+\.\s+[^\n]{5,80}', text))
    if numbered_lines >= 5:
        return False

    if re.match(r'^제\d+[장절]', text.strip()):
        return False

    return True


def load_kisa_pdfs(kisa_path: Path) -> list:
    """KISA PDF 통으로 로드"""
    print(f"\n📄 KISA PDF 로드 중: {kisa_path}")

    if not kisa_path.exists():
        print(f"❌ 경로를 찾을 수 없습니다: {kisa_path}")
        sys.exit(1)

    documents = []
    pdf_files = list(kisa_path.glob("*.pdf"))

    if not pdf_files:
        print(f"❌ PDF 파일을 찾을 수 없습니다")
        sys.exit(1)

    print(f"   찾은 PDF 파일: {len(pdf_files)}개")

    for pdf_file in tqdm(pdf_files, desc="PDF 로딩"):
        lang = 'java' if 'java' in pdf_file.name.lower() else 'python'

        loader = PyPDFLoader(str(pdf_file))
        pages = loader.load()

        for page in pages:
            cleaned_text = clean_pdf_text(page.page_content)

            if len(cleaned_text) < 300:
                continue

            doc = Document(
                page_content=cleaned_text,
                metadata={
                    "source_type": "KISA_SecureCoding",
                    "language": lang,
                    "source": pdf_file.name,
                    "page": page.metadata.get("page", 0)
                }
            )
            documents.append(doc)

    print(f"✅ {len(documents)}개 페이지 로드 완료")
    return documents


def init_qdrant_collection(client: QdrantClient, collection_name: str, vector_dim: int):
    """Qdrant 컬렉션 초기화"""
    print(f"\n📦 컬렉션 '{collection_name}' 초기화 중...")

    if client.collection_exists(collection_name):
        print(f"   기존 컬렉션 삭제 중...")
        client.delete_collection(collection_name)

    client.create_collection(
        collection_name=collection_name,
        vectors_config=VectorParams(size=vector_dim, distance=Distance.COSINE)
    )
    print(f"✅ 컬렉션 준비 완료")


def index_to_qdrant(documents: list, collection_name: str, client: QdrantClient):
    """문서를 Qdrant에 임베딩"""
    print(f"\n🔄 임베딩 생성 및 업로드 중...")

    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        length_function=len
    )

    chunks = text_splitter.split_documents(documents)
    print(f"   📝 {len(documents)}개 페이지 → {len(chunks)}개 청크")

    filtered_chunks = [c for c in chunks if is_useful_chunk(c.page_content)]
    print(f"   ✅ 유효 청크: {len(filtered_chunks)}개")

    print(f"   🧠 임베딩 생성 중...")
    text_list = [c.page_content for c in filtered_chunks]
    vectors = EMBEDDING_MODEL.embed_documents(text_list)
    print(f"   ✅ {len(vectors)}개 임베딩 생성 완료")

    print(f"   ⬆️ Qdrant 업로드 중...")
    uploaded = 0

    for i in tqdm(range(0, len(filtered_chunks), BATCH_SIZE), desc="업로드"):
        batch_chunks = filtered_chunks[i:i + BATCH_SIZE]
        batch_vectors = vectors[i:i + BATCH_SIZE]
        points = []

        for j, doc in enumerate(batch_chunks):
            points.append(
                models.PointStruct(
                    id=i + j + 1,
                    vector=batch_vectors[j],
                    payload={**doc.metadata, "page_content": doc.page_content}
                )
            )

        client.upsert(collection_name=collection_name, points=points, wait=True)
        uploaded += len(points)

    print(f"✅ {uploaded}개 청크 임베딩 완료")
    return uploaded


def main():
    print("=" * 60)
    print("🧪 KISA 가이드라인 RAW 임베딩 (통으로 처리)")
    print("=" * 60)

    print(f"\n🔌 Qdrant 연결: {QDRANT_URL}")
    client = QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY, prefer_grpc=False)
    print("✅ 연결 성공")

    init_qdrant_collection(client, COLLECTION_NAME, TEXT_VECTOR_DIMENSION)

    kisa_docs = load_kisa_pdfs(KISA_DATA_PATH)

    count = index_to_qdrant(kisa_docs, COLLECTION_NAME, client)

    print("\n" + "=" * 60)
    print("📊 최종 결과")
    print("=" * 60)

    collection_info = client.get_collection(collection_name=COLLECTION_NAME)
    print(f"컬렉션: {COLLECTION_NAME}")
    print(f"벡터 개수: {collection_info.points_count:,}")
    print(f"청크 크기: {CHUNK_SIZE} (큰 맥락)")
    print(f"방식: PDF 직접 임베딩 (OWASP 방식)")

    print("\n" + "=" * 60)
    print("🎉 완료! test_kisa.py 실행하세요")
    print("=" * 60)


if __name__ == "__main__":
    main()
