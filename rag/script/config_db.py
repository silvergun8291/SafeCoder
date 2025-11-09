"""
RAG 파이프라인 전역 설정 파일

Qdrant, 임베딩 모델, 데이터 경로 등 모든 설정을 중앙에서 관리합니다.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

# ==================== Qdrant 설정 ====================
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
QDRANT_API_KEY = os.getenv("QDRANT_API_KEY")

# ==================== 임베딩 모델 설정 ====================
UPSTAGE_API_KEY = os.getenv("UPSTAGE_API_KEY")

# ==================== 프로젝트 경로 설정 ====================
# config_db.py 위치: rag2/script/config_db.py
# 프로젝트 루트: rag2/
PROJECT_ROOT = Path(__file__).parent.parent
DATA_ROOT = PROJECT_ROOT / "data"

# ==================== Code RAG 설정 ====================
CODE_COLLECTION_NAME = "secure_coding_knowledge_qdrant"
CODE_EMBEDDING_MODEL = "sentence-transformers/multi-qa-distilbert-cos-v1"
CODE_VECTOR_DIMENSION = 768
CODE_RAW_DATA_PATH = DATA_ROOT / "raw" / "code"
CODE_EMBEDDINGS_CSV = DATA_ROOT / "processed" / "secure_coding_embeddings_ver3.csv"

# ==================== Text RAG 설정 ====================
TEXT_COLLECTION_NAME = "text_db"
RULE_COLLECTION_NAME = "rule_db"
TEXT_EMBEDDING_MODEL = "solar-embedding-1-large"
TEXT_VECTOR_DIMENSION = 4096

# Text RAG 데이터 경로 (세부)
TEXT_DATA_ROOT = DATA_ROOT / "raw" / "text"
KISA_DATA_PATH = TEXT_DATA_ROOT / "kisa_guidelines" / "pdf"
OWASP_DATA_PATH = TEXT_DATA_ROOT / "owasp_cheatsheet"
SEMGREP_DATA_PATH = TEXT_DATA_ROOT / "semgrep_docs"

# 하위 호환성을 위한 기존 경로 (deprecated)
TEXT_DATA_PATH = DATA_ROOT / "raw"
