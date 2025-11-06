# rag2/script/code_rag/load_code_qdrant.py (Code RAG 로더 스크립트)

import pandas as pd
import json
import sys
import uuid
import os
import ast
from pathlib import Path
from qdrant_client import QdrantClient, models
from qdrant_client.models import Distance, VectorParams
from tqdm import tqdm

# --- config_db.py에서 설정 임포트 ---
# 현재 파일 위치: .../rag2/script/code_rag
# config_db 위치: .../rag2/script
config_dir = Path(__file__).resolve().parent.parent

if str(config_dir) not in sys.path:
    sys.path.insert(0, str(config_dir))

try:
    import config_db

    QDRANT_URL = config_db.QDRANT_URL
    CODE_COLLECTION_NAME = config_db.CODE_COLLECTION_NAME
    CODE_EMBEDDINGS_CSV = config_db.CODE_EMBEDDINGS_CSV  # ✨ config_db의 Path 객체 사용
    CODE_VECTOR_DIMENSION = config_db.CODE_VECTOR_DIMENSION

except ImportError as e:
    print(f"🚨 치명적 오류: config_db.py 임포트 실패: {e}")
    sys.exit(1)


# --- 2. Qdrant 컬렉션 초기화 (Deprecation Warning 해결 포함) ---
def init_qdrant_collection(client: QdrantClient):
    """Qdrant 컬렉션을 초기화하거나 새로 생성합니다."""

    collection_name = CODE_COLLECTION_NAME
    vector_dim = CODE_VECTOR_DIMENSION

    # Deprecation 해결: recreate_collection 대신 create_collection/delete_collection 사용
    try:
        print(f"Qdrant 컬렉션 '{collection_name}'을 초기화합니다.")
        if client.collection_exists(collection_name):
            client.delete_collection(collection_name)

        client.create_collection(
            collection_name=collection_name,
            vectors_config=VectorParams(size=vector_dim, distance=Distance.COSINE)
        )
        print(f"컬렉션 '{collection_name}' (차원: {vector_dim}, 거리: COSINE) 준비 완료.")
    except Exception as e:
        print(f"🚨 Error: Qdrant 컬렉션 초기화 중 오류 발생. {e}")
        sys.exit(1)


def upload_vectors_to_qdrant():
    """CSV 파일을 읽어 Qdrant에 벡터와 페이로드를 업로드합니다."""

    # 1. Qdrant 클라이언트 연결 및 컬렉션 초기화 (유지)
    try:
        client = QdrantClient(url=QDRANT_URL)
        init_qdrant_collection(client)
        print(f"Qdrant 연결 성공. '{CODE_COLLECTION_NAME}' 컬렉션에 업로드를 시작합니다.")

    except Exception as e:
        print(f"🚨 Error: Qdrant 서버 연결에 실패했습니다. {QDRANT_URL}")
        print("1. Qdrant Docker 또는 서버가 실행 중인지 확인하세요.")
        print(f"Error details: {e}")
        sys.exit(1)

    # 2. CSV 파일 로드 및 전처리
    # 💡 config_db에서 가져온 Path 객체를 사용합니다.
    full_path = CODE_EMBEDDINGS_CSV
    print(f"Loading data from '{full_path}'...")

    try:
        df = pd.read_csv(full_path)

        # Colab에서 문자열로 저장된 'vector'와 'payload_json'을 실제 객체로 변환
        # ast.literal_eval을 사용하기 전에, 'vector' 필드가 리스트 형태의 문자열인지 확인해야 합니다.
        df['vector'] = df['vector'].apply(ast.literal_eval)
        df['payload'] = df['payload_json'].apply(json.loads)

    except FileNotFoundError:
        print(f"🚨 Error: '{full_path}' 파일을 찾을 수 없습니다.")
        print("파일이 'data/processed/' 폴더에 있는지 확인하세요.")
        sys.exit(1)
    except Exception as e:
        print(f"파일 로드 및 처리 중 에러 발생: {e}")
        sys.exit(1)

    # 3. Qdrant에 데이터 삽입 (배치 처리)
    # ... (업로드 로직 유지)
    batch_points = []
    BATCH_SIZE = 128

    # Colab에서 생성된 CSV는 'id' 컬럼을 가지고 있으므로, 이를 재활용하거나 새로 생성 가능합니다.
    # 여기서는 CSV의 id를 사용하지 않고 UUID를 새로 생성하여 충돌 위험을 줄입니다.

    print(f"총 {len(df)}개의 데이터 포인트를 업로드합니다.")
    for index, row in tqdm(df.iterrows(), total=len(df), desc=f"Uploading to {CODE_COLLECTION_NAME}"):

        # 💡 ID는 Qdrant가 요구하는 정수(int) 타입 또는 UUID 문자열을 사용합니다.
        # Colab에서 생성한 CSV에는 'id' 컬럼이 정수형으로 있으므로, 그 값을 재활용하겠습니다.
        point_id = int(row['id'])

        point = models.PointStruct(
            id=point_id,  # CSV의 정수 ID를 그대로 사용
            vector=row['vector'],
            payload=row['payload']
        )
        batch_points.append(point)

        # 배치가 꽉 차면 업로드
        if len(batch_points) >= BATCH_SIZE:
            client.upsert(
                collection_name=CODE_COLLECTION_NAME,
                points=batch_points,
                wait=True
            )
            batch_points.clear()

    # 4. 남은 배치 업로드
    if batch_points:
        client.upsert(
            collection_name=CODE_COLLECTION_NAME,
            points=batch_points,
            wait=True
        )

    # 5. 최종 결과 확인
    count_result = client.count(collection_name=CODE_COLLECTION_NAME, exact=True)
    print(f"\n--- 🚀 Upload Complete ---")
    print(f"Total points uploaded to '{CODE_COLLECTION_NAME}': {count_result.count}개")
    print("Code RAG 벡터 DB 구축이 최종 완료되었습니다.")


if __name__ == "__main__":
    upload_vectors_to_qdrant()