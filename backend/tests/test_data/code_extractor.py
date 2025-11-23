import json


def format_rejected_code(data_list, index_to_extract):
    """
    주어진 인덱스에 해당하는 데이터에서 rejected 코드를 추출하고 포맷팅하여 출력합니다.
    """
    try:
        entry = data_list[index_to_extract - 1]

        # 추출할 정보
        lang = entry.get("lang", "N/A")
        vulnerability = entry.get("vulnerability", "N/A")
        question = entry.get("question", "N/A")
        rejected_code = entry.get("rejected", "N/A")

        # 출력 포맷팅
        print("=" * 80)
        print(f"| \033[1mEntry Index:\033[0m {index_to_extract}")
        print(f"| \033[1mLanguage:\033[0m {lang.upper()}")
        print("=" * 80)

        print(f"\033[1mVulnerability Context:\033[0m {vulnerability}")
        print("\n" + "-" * 30)
        print(f"\033[1mQuestion:\033[0m")
        print(f"{question}")
        print("-" * 30)

        print(f"\n\033[1mRejected Code (Vulnerable/Non-Optimal):\033[0m")
        print("```" + lang)
        print(rejected_code.strip())
        print("```")
        print("=" * 80)

    except IndexError:
        print(f"오류: 인덱스 {index_to_extract}는 데이터 범위를 벗어납니다. (0부터 {len(data_list) - 1}까지)")
    except Exception as e:
        print(f"데이터 처리 중 오류가 발생했습니다: {e}")


# 1. JSON 파일 로드
file_name = './test_set.json'
with open(file_name, 'r', encoding='utf-8') as f:
    data = json.load(f)

# 2. 추출을 원하는 항목의 인덱스 지정 (예시: 첫 번째 항목)
index_to_extract = 123

# 3. 함수 실행 및 결과 출력
format_rejected_code(data, index_to_extract)