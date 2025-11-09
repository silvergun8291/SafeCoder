import json
from typing import List, Dict, Any


def clean_secure_code_only(input_filename: str, output_filename: str) -> int:
    """
    JSON 파일에서 'safe_code' 또는 'patched_code' 필드에 안티패턴이 포함된 항목만 제거합니다.
    다른 필드(vulnerable_code 등)에 패턴이 있어도 제거하지 않습니다.
    """
    # LLM이 생성할 '안전한' 코드에 절대 포함되어서는 안 되는 안티패턴 목록
    ALL_ANTI_PATTERNS = [
        "new Thread(",
        "implements Runnable",
        ".join()",
        "Thread.sleep",
        "StreamConsumer",
        ".getCanonicalPath()",
        "new File(",
        "factory.setValidating(false)",
        "finally {",
        "new FileInputStream(",
        "new String(data)"
    ]

    # 보안 코드 내용을 담고 있을 것으로 예상되는 키 목록
    SECURE_CODE_KEYS = ['safe_code', 'patched_code']

    try:
        with open(input_filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"❌ 오류: 파일 '{input_filename}'을 찾을 수 없습니다.")
        return 0
    except json.JSONDecodeError:
        print(f"❌ 오류: 파일 '{input_filename}'의 JSON 형식이 잘못되었습니다.")
        return 0

    if not isinstance(data, list):
        print("⚠️ 경고: 데이터가 목록 형식이 아닙니다. 필터링을 건너뜁니다.")
        return 0

    cleaned_data = []
    removed_count = 0

    for item in data:
        if not isinstance(item, dict):
            cleaned_data.append(item)
            continue

        should_keep = True

        # SECURE_CODE_KEYS에 해당하는 모든 필드를 검사
        for key in SECURE_CODE_KEYS:
            field_content = item.get(key)

            if isinstance(field_content, str):
                # 대소문자 구분 없이 확인
                content_lower = field_content.lower()

                for pattern in ALL_ANTI_PATTERNS:
                    if pattern.lower() in content_lower:
                        should_keep = False
                        # print(f"제거 사유: '{pattern}' 패턴이 '{key}' 필드에서 발견됨") # 디버깅용
                        break

            if not should_keep:
                break

        if should_keep:
            cleaned_data.append(item)
        else:
            removed_count += 1

    # 클리닝된 데이터를 새 파일에 저장
    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(cleaned_data, f, indent=2, ensure_ascii=False)
        print(f"✅ 클리닝 완료: '{input_filename}'에서 {removed_count}개 항목 제거됨. 클리닝된 데이터는 '{output_filename}'에 저장됨.")
    except Exception as e:
        print(f"❌ 오류: 클리닝된 데이터를 저장하는 중 오류 발생: {e}")

    return removed_count


# 두 JSON 파일에 대해 클리닝 함수 호출
files_to_clean = [
    ("java_megavul.json", "java_megavul_refined_cleaned.json"),
    ("java_dpo.json", "java_dpo_refined_cleaned.json")
]

total_removed = 0
for input_file, output_file in files_to_clean:
    total_removed += clean_secure_code_only(input_file, output_file)

print(f"\n총 {total_removed}개 항목이 두 파일에서 제거되었습니다. 이 데이터로 Vector DB를 재구축해야 합니다.")