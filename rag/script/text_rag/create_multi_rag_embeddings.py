import os
import sys
import argparse
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
except ImportError as e:
    print(f"🚨 config_db.py 임포트 실패: {e}")
    sys.exit(1)

os.environ["UPSTAGE_API_KEY"] = UPSTAGE_API_KEY
EMBEDDING_MODEL = UpstageEmbeddings(model=TEXT_EMBEDDING_MODEL)

# 컬렉션 이름
COLLECTIONS = {
    "kisa": "kisa_text_db",
    "owasp": "owasp_text_db",
    "semgrep": "semgrep_rule_db"
}

# 임베딩 설정
CHUNK_SIZE = 2000
CHUNK_OVERLAP = 500
BATCH_SIZE = 32

# ✅ 데이터 디렉토리 경로 (수정됨)
DATA_BASE_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "raw" / "text"
KISA_PDF_PATH = DATA_BASE_PATH / "kisa_guidelines"  # ✅ 변경됨
OWASP_MD_PATH = DATA_BASE_PATH / "owasp_cheatsheet"
SEMGREP_MD_PATH = DATA_BASE_PATH / "semgrep_docs"


def clean_pdf_text(text: str) -> str:
    """PDF 텍스트 정제"""
    text = re.sub(r'\n\d+\s+PART\s+\d+.*?\n', '\n', text)
    text = re.sub(r'\nPART\s+\d+.*?\n', '\n', text)
    text = re.sub(r'\n\d+:\s*', '\n', text)
    text = re.sub(r'(\d+:){2,}', '', text)
    text = re.sub(r'<br\s*/?>', ' ', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def is_useful_chunk(text: str) -> bool:
    """유용한 청크 판단"""
    txt = text.strip()
    if len(txt) < 300:
        # Semgrep autofix 관련 키워드가 있으면 길이가 짧아도 유지
        low = txt.lower()
        if "autofix" in low or "\nfix:" in low or low.startswith("fix:"):
            return True
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


def load_kisa_pdfs(kisa_path: Path) -> list:
    """KISA PDF 로드"""
    print(f"\n📄 KISA PDF 로드 중: {kisa_path}")

    if not kisa_path.exists():
        print(f"❌ 경로 없음: {kisa_path}")
        print(f"   ℹ️  예상 경로: {kisa_path}")
        return []

    documents = []
    # ✅ 하위 모든 디렉토리에서 PDF 찾기
    pdf_files = list(kisa_path.rglob("*.pdf"))

    if not pdf_files:
        print(f"❌ PDF 파일 없음")
        return []

    print(f"   찾은 PDF: {len(pdf_files)}개")

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
                    "source_type": "KISA",
                    "language": lang,
                    "source": pdf_file.name,
                    "page": page.metadata.get("page", 0)
                }
            )
            documents.append(doc)

    print(f"✅ {len(documents)}개 페이지 로드 완료")
    return documents


def load_owasp_md(owasp_dir: Path) -> list:
    """OWASP Cheatsheet MD 파일 로드"""
    print(f"\n📄 OWASP Cheatsheet MD 로드 중: {owasp_dir}")

    if not owasp_dir.exists():
        print(f"❌ 디렉터리 없음: {owasp_dir}")
        print(f"   ℹ️  예상 경로: {owasp_dir}")
        return []

    documents = []
    md_files = list(owasp_dir.glob("*.md"))

    if not md_files:
        print(f"❌ MD 파일 없음")
        return []

    print(f"   찾은 MD: {len(md_files)}개")

    for md_file in tqdm(md_files, desc="MD 로딩"):
        try:
            with open(md_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Semgrep 문서는 작은 파일도 중요도가 높아 필터링하지 않음

            title = md_file.stem.replace('-', ' ').replace('_', ' ').title()

            doc = Document(
                page_content=content,
                metadata={
                    "source_type": "OWASP",
                    "title": title,
                    "source": md_file.name,
                    "file_type": "markdown"
                }
            )
            documents.append(doc)
        except Exception as e:
            print(f"   ⚠️ {md_file.name}: {e}")

    print(f"✅ {len(documents)}개 MD 파일 로드 완료")
    return documents


def load_semgrep_md(semgrep_dir: Path) -> list:
    """Semgrep 규칙 MD 파일 로드"""
    print(f"\n📄 Semgrep 규칙 MD 로드 중: {semgrep_dir}")

    if not semgrep_dir.exists():
        print(f"❌ 디렉터리 없음: {semgrep_dir}")
        print(f"   ℹ️  예상 경로: {semgrep_dir}")
        return []

    documents = []
    md_files = list(semgrep_dir.glob("*.md"))

    if not md_files:
        print(f"❌ MD 파일 없음")
        return []

    print(f"   찾은 MD: {len(md_files)}개")

    for md_file in tqdm(md_files, desc="MD 로딩"):
        try:
            with open(md_file, 'r', encoding='utf-8') as f:
                content = f.read()

            if len(content) < 300:
                continue

            rule_id = md_file.stem
            title = rule_id.replace('-', ' ').replace('_', ' ').title()

            lines = content.split('\n')
            if lines and lines[0].startswith('#'):
                title = lines[0].replace('#', '').strip()

            doc = Document(
                page_content=content,
                metadata={
                    "source_type": "Semgrep",
                    "rule_id": rule_id,
                    "title": title,
                    "source": md_file.name,
                    "file_type": "markdown"
                }
            )
            documents.append(doc)
        except Exception as e:
            print(f"   ⚠️ {md_file.name}: {e}")

    print(f"✅ {len(documents)}개 MD 파일 로드 완료")
    return documents


def init_qdrant_collection(client: QdrantClient, collection_name: str, vector_dim: int):
    """Qdrant 컬렉션 초기화"""
    print(f"   📦 컬렉션 '{collection_name}' 초기화...")

    if client.collection_exists(collection_name):
        client.delete_collection(collection_name)

    client.create_collection(
        collection_name=collection_name,
        vectors_config=VectorParams(size=vector_dim, distance=Distance.COSINE)
    )


def index_to_qdrant(documents: list, collection_name: str, client: QdrantClient):
    """문서를 Qdrant에 임베딩"""
    if not documents:
        print(f"   ⚠️ 문서 없음")
        return 0

    print(f"   🔄 임베딩 생성 중...")
    
    # 컬렉션별 청킹 전략
    is_semgrep = collection_name == COLLECTIONS.get("semgrep")
    if is_semgrep:
        # Semgrep은 더 세밀한 청킹과 작은 파일 통짜 업로드를 사용
        semgrep_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            length_function=len
        )
        chunks = []
        for doc in documents:
            content = doc.page_content or ""
            if len(content) <= 5000:
                # 작은 파일은 통짜 업로드
                chunks.append(doc)
            else:
                # 큰 파일만 분할
                chunks.extend(semgrep_splitter.split_documents([doc]))
        # 유용 청크 필터 + 키워드 예외는 is_useful_chunk에서 처리
        filtered_chunks = [c for c in chunks if is_useful_chunk(c.page_content)]
        # 파일당 최대 청크 수 제한으로 과도한 중복 방지 (예: rule-syntax.md 편중 완화)
        MAX_CHUNKS_PER_SOURCE = 30
        buckets = {}
        capped_chunks = []
        for c in filtered_chunks:
            src = (c.metadata or {}).get("source", "")
            cnt = buckets.get(src, 0)
            if cnt < MAX_CHUNKS_PER_SOURCE:
                capped_chunks.append(c)
                buckets[src] = cnt + 1
        filtered_chunks = capped_chunks
    else:
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=CHUNK_SIZE,
            chunk_overlap=CHUNK_OVERLAP,
            length_function=len
        )
        chunks = text_splitter.split_documents(documents)
        filtered_chunks = [c for c in chunks if is_useful_chunk(c.page_content)]

    if not filtered_chunks:
        print(f"   ❌ 유효한 청크 없음")
        return 0

    print(f"   {len(documents)} → {len(chunks)} → {len(filtered_chunks)} 청크")

    text_list = [c.page_content for c in filtered_chunks]
    vectors = EMBEDDING_MODEL.embed_documents(text_list)

    print(f"   ⬆️ 임베딩 업로드 중...")
    uploaded = 0

    for i in tqdm(range(0, len(filtered_chunks), BATCH_SIZE), desc="업로드", leave=False):
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

    print(f"   ✅ {uploaded}개 벡터 생성")
    return uploaded


def main():
    parser = argparse.ArgumentParser(description="텍스트 DB 생성 (KISA/OWASP/Semgrep)")
    parser.add_argument("--semgrep-only", action="store_true", help="Semgrep 규칙 DB만 생성/업데이트")
    args = parser.parse_args()

    print("=" * 70)
    print("🧪 텍스트 DB 생성 (KISA + OWASP + Semgrep MD)")
    print("=" * 70)

    # ✅ 경로 출력 (디버깅용)
    print(f"\n📁 데이터 디렉토리 구조:")
    print(f"   - KISA PDF: {KISA_PDF_PATH}")
    print(f"   - OWASP MD: {OWASP_MD_PATH}")
    print(f"   - Semgrep MD: {SEMGREP_MD_PATH}")

    print(f"\n🔌 Qdrant 연결: {QDRANT_URL}")
    client = QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY, prefer_grpc=False)
    print("✅ 연결 성공\n")

    results = {}

    if args.semgrep_only:
        print("=" * 70)
        print("📝 Semgrep 규칙 DB 생성 (MD 파일)")
        print("=" * 70)
        init_qdrant_collection(client, COLLECTIONS["semgrep"], TEXT_VECTOR_DIMENSION)
        semgrep_docs = load_semgrep_md(SEMGREP_MD_PATH)
        results["semgrep"] = index_to_qdrant(semgrep_docs, COLLECTIONS["semgrep"], client)
    else:
        # 1. KISA DB
        print("=" * 70)
        print("📝 1. KISA 텍스트 DB 생성")
        print("=" * 70)
        init_qdrant_collection(client, COLLECTIONS["kisa"], TEXT_VECTOR_DIMENSION)
        kisa_docs = load_kisa_pdfs(KISA_PDF_PATH)
        results["kisa"] = index_to_qdrant(kisa_docs, COLLECTIONS["kisa"], client)

        # 2. OWASP DB (MD 파일)
        print("\n" + "=" * 70)
        print("📝 2. OWASP 텍스트 DB 생성 (Cheatsheet MD)")
        print("=" * 70)
        init_qdrant_collection(client, COLLECTIONS["owasp"], TEXT_VECTOR_DIMENSION)
        owasp_docs = load_owasp_md(OWASP_MD_PATH)
        results["owasp"] = index_to_qdrant(owasp_docs, COLLECTIONS["owasp"], client)

        # 3. Semgrep DB (MD 파일)
        print("\n" + "=" * 70)
        print("📝 3. Semgrep 규칙 DB 생성 (MD 파일)")
        print("=" * 70)
        init_qdrant_collection(client, COLLECTIONS["semgrep"], TEXT_VECTOR_DIMENSION)
        semgrep_docs = load_semgrep_md(SEMGREP_MD_PATH)
        results["semgrep"] = index_to_qdrant(semgrep_docs, COLLECTIONS["semgrep"], client)

    # 완료 요약
    print("\n" + "=" * 70)
    print("✅ DB 생성 완료")
    print("=" * 70)

    total = 0
    for name, count in results.items():
        print(f"📊 {name.upper():8} ({COLLECTIONS[name]:20}): {count:6,}개 벡터")
        total += count

    print("-" * 70)
    print(f"🎯 총합: {total:,}개 벡터")
    print("=" * 70)

if __name__ == "__main__":
    main()