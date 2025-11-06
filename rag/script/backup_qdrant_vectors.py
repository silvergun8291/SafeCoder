# rag2/script/text/backup_qdrant_vectors.py

import os
import sys
import pandas as pd
import json
from typing import List, Dict, Any
from pathlib import Path
from qdrant_client import QdrantClient, models
from tqdm import tqdm
import traceback # ✨ traceback 모듈 임포트 추가

# --- 설정 파일 임포트 ---
config_dir = Path(__file__).resolve().parent.parent
if str(config_dir) not in sys.path:
    sys.path.insert(0, str(config_dir))

try:
    import config_db

    QDRANT_URL = config_db.QDRANT_URL
    QDRANT_API_KEY = config_db.QDRANT_API_KEY
    TEXT_COLLECTION_NAME = config_db.TEXT_COLLECTION_NAME
    RULE_COLLECTION_NAME = config_db.RULE_COLLECTION_NAME
    TEXT_EMBEDDINGS_CSV = config_db.TEXT_EMBEDDINGS_CSV
    RULE_EMBEDDINGS_CSV = config_db.RULE_EMBEDDINGS_CSV
    TEXT_VECTOR_DIMENSION = config_db.TEXT_VECTOR_DIMENSION
except ImportError as e:
    print(f"🚨 치명적 오류: config_db.py 임포트 실패: {e}")
    sys.exit(1)


# --- 3. Qdrant 데이터 추출 및 CSV 저장 로직 ---

def extract_and_save(client: QdrantClient, collection_name: str, output_path: Path):
    """지정된 Qdrant 컬렉션의 모든 벡터와 페이로드를 추출하여 CSV로 저장합니다."""

    print(f"\n==============================================")
    print(f"💾 컬렉션 '{collection_name}' 백업 시작")
    print(f"==============================================")

    try:
        # 컬렉션 정보 확인
        collection_info = client.get_collection(collection_name=collection_name)
        total_count = collection_info.points_count
        if total_count == 0:
            print(f"⚠️ 컬렉션 '{collection_name}'에 저장된 포인트가 없습니다. 백업을 건너뜁니다.")
            return

        print(f"총 {total_count}개 포인트를 추출합니다...")

        all_points_data = []
        scroll_offset = None

        # Qdrant의 scroll 기능을 사용하여 모든 포인트 추출
        with tqdm(total=total_count, desc=f"추출: {collection_name}") as pbar:
            while True:
                points, next_offset = client.scroll(
                    collection_name=collection_name,
                    scroll_filter=None,
                    limit=256,
                    with_payload=True,
                    with_vectors=True,
                    offset=scroll_offset
                )

                for point in points:
                    # 벡터를 리스트로, 페이로드를 JSON 문자열로 직렬화
                    payload_json = json.dumps(point.payload, ensure_ascii=False)

                    all_points_data.append({
                        "id": str(point.id),
                        "vector": point.vector,  # ✨ TypeError 해결: point.vector를 직접 사용
                        "payload_json": payload_json
                    })

                pbar.update(len(points))

                if next_offset is None:
                    break
                scroll_offset = next_offset

        # DataFrame으로 변환 및 저장
        df = pd.DataFrame(all_points_data)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        # ast.literal_eval로 복원 가능하도록 리스트를 문자열로 저장
        df['vector'] = df['vector'].apply(str)
        df.to_csv(output_path, index=False)

        print(f"✅ 백업 완료! {total_count}개 포인트를 '{output_path}'에 저장했습니다.")

    except Exception as e:
        print(f"🚨 백업 중 치명적인 오류 발생: {e}")
        traceback.print_exc() # ✨ NameError 해결: traceback 임포트 후 사용
        sys.exit(1)


def main():
    """메인 백업 실행 함수"""
    try:
        # Qdrant 클라이언트 연결
        client = QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY)
        client.get_collections()

    except Exception as e:
        print(f"🚨 Qdrant 서버 연결에 실패했습니다. {QDRANT_URL}")
        print("Qdrant Docker 또는 서버가 실행 중인지 확인하세요.")
        sys.exit(1)

    # 1. Text DB 백업
    extract_and_save(client, TEXT_COLLECTION_NAME, TEXT_EMBEDDINGS_CSV)

    # 2. Rule DB 백업
    extract_and_save(client, RULE_COLLECTION_NAME, RULE_EMBEDDINGS_CSV)

    print("\n🎉 모든 Text RAG 벡터 백업 작업이 완료되었습니다!")


if __name__ == "__main__":
    main()