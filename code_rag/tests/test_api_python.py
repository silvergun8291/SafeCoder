# tests/test_api_python.py

import httpx
import json
import sys

# FastAPI 서버 엔드포인트
API_URL = "http://localhost:8000/query_code"

# --- ⬇️ Python SQL Injection 스캔 결과 예시 ⬇️ ---
test_payload = {
    # 취약한 Python 코드 조각 (f-string을 사용한 SQL 쿼리)
    "code_snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\"\\ncursor.execute(query)",
    "cwe_id": "CWE-89",  # SQL Injection
    "language": "python",
    "top_k": 3,
    "description": "Detected possible formatted SQL query. Use parameterized queries instead of f-strings."
}


# --- ⬆️ Python SQL Injection 스캔 결과 예시 ⬆️ ---


def run_python_test():
    """Python SQL Injection 테스트를 실행하고 결과를 출력합니다."""
    print("=" * 60)
    print(f"🐍 Python 테스트: SQL Injection (CWE-{test_payload['cwe_id']})")
    print(f"요청 URL: {API_URL}")
    print(f"요청 데이터: {json.dumps(test_payload, indent=2)}")
    print("=" * 60)

    try:
        # httpx 클라이언트를 사용하여 요청 (requests 대신 더 현대적인 라이브러리 사용)
        response = httpx.post(API_URL, json=test_payload, timeout=10.0)
        response.raise_for_status()  # 200 이외의 응답 코드는 예외 발생

        response_data = response.json()
        retrieved_docs = response_data.get('retrieved_documents', [])

        print(f"\n--- ✅ 요청 성공! (HTTP Status: {response.status_code}) ---")
        print(f"총 검색된 문서 수: {len(retrieved_docs)}개")

        for i, doc in enumerate(retrieved_docs):
            payload = doc['payload']
            print(f"\n--- [검색 결과 {i + 1}] (유사도: {doc['score']:.4f}) ---")
            print(f"CWE-ID: {payload['cwe_id']}")
            print(f"취약점 요약: {payload['description']}")
            print(f"\n[취약한 코드 예시]\n{payload['vulnerable_code'][:250]}...")
            print(f"\n[안전한 코드 예시]\n{payload['safe_code'][:250]}...")

    except httpx.ConnectError as e:
        print(f"\n❌ 테스트 실패: FastAPI 서버 연결 오류. 서버가 실행 중인지 확인하세요. (Error: {e})")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        print(f"\n❌ 테스트 실패: HTTP 오류 발생. (Status: {e.response.status_code}, Detail: {e.response.text})")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 테스트 중 예상치 못한 오류 발생: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_python_test()