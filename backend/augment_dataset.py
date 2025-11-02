import json
import os
import copy
from typing import List, Dict, Any, Set

# --- 일반적인 CWE 취약점/안전 코드 템플릿 ---
# 스캐너가 100% 탐지해야 하는 "교과서적인" 예제들입니다.
# 각 CWE별로 2~3개의 다양한 패턴을 제공합니다.
CWE_EXAMPLE_TEMPLATES = {
    "CWE-89": [
        {
            "vulnerability_summary": "SQL Injection (Classic Statement)",
            "vulnerable_code": """
public User getUser(String userInput) throws SQLException {
    Connection con = DriverManager.getConnection(DB_URL, USER, PASS);
    Statement stmt = con.createStatement();
    String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
    ResultSet rs = stmt.executeQuery(query); // 🚨 VULNERABLE
    // ...
}
""",
            "safe_code": """
public User getUser(String userInput) throws SQLException {
    Connection con = DriverManager.getConnection(DB_URL, USER, PASS);
    String query = "SELECT * FROM users WHERE username = ?";
    PreparedStatement stmt = con.prepareStatement(query);
    stmt.setString(1, userInput);
    ResultSet rs = stmt.executeQuery(); // ✅ SAFE
    // ...
}
"""
        },
        {
            "vulnerability_summary": "SQL Injection (Login)",
            "vulnerable_code": """
public boolean login(String user, String pass) throws SQLException {
    Statement stmt = db.getConnection().createStatement();
    String sql = "SELECT * FROM accounts WHERE user = '" + user + 
                 "' AND pass = '" + pass + "'";
    ResultSet rs = stmt.executeQuery(sql); // 🚨 VULNERABLE
    return rs.next();
}
""",
            "safe_code": """
public boolean login(String user, String pass) throws SQLException {
    String sql = "SELECT * FROM accounts WHERE user = ? AND pass = ?";
    PreparedStatement stmt = db.getConnection().prepareStatement(sql);
    stmt.setString(1, user);
    stmt.setString(2, pass);
    ResultSet rs = stmt.executeQuery(); // ✅ SAFE
    return rs.next();
}
"""
        }
    ],
    "CWE-79": [
        {
            "vulnerability_summary": "Cross-Site Scripting (XSS)",
            "vulnerable_code": """
public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String name = request.getParameter("name");
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    out.println("<html><body>");
    out.println("<h1>Hello, " + name + "</h1>"); // 🚨 VULNERABLE
    out.println("</body></html>");
}
""",
            "safe_code": """
// (OWASP ESAPI 또는 유사 라이브러리 필요)
// import org.owasp.encoder.Encode;
public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String name = request.getParameter("name");
    // String safeName = Encode.forHtml(name); // ✅ SAFE (Recommended)

    // 간단한 수동 이스케이프 (예시)
    String safeName = name.replace("<", "&lt;").replace(">", "&gt;");

    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    out.println("<html><body>");
    out.println("<h1>Hello, " + safeName + "</h1>"); // ✅ SAFE
    out.println("</body></html>");
}
"""
        }
    ],
    "CWE-22": [
        {
            "vulnerability_summary": "Path Traversal",
            "vulnerable_code": """
public void readFile(String filename) throws IOException {
    // 사용자가 "..\..\etc\passwd" 같은 값을 입력 가능
    String fullPath = "/var/www/data/" + filename;
    File file = new File(fullPath); // 🚨 VULNERABLE
    FileInputStream fis = new FileInputStream(file);
    // ... read file
}
""",
            "safe_code": """
public void readFile(String filename) throws IOException {
    File baseDir = new File("/var/www/data/");
    File file = new File(baseDir, filename);

    // 경로 정규화 및 검증
    String canonicalPath = file.getCanonicalPath();
    if (!canonicalPath.startsWith(baseDir.getCanonicalPath())) {
        throw new SecurityException("Path Traversal attempt detected!");
    }

    FileInputStream fis = new FileInputStream(file); // ✅ SAFE
    // ... read file
}
"""
        }
    ],
    "CWE-78": [
        {
            "vulnerability_summary": "OS Command Injection",
            "vulnerable_code": """
public void listFiles(String directory) throws IOException {
    // 사용자가 ".; ls /" 같은 값을 입력 가능
    Process p = Runtime.getRuntime().exec("ls " + directory); // 🚨 VULNERABLE
    // ...
}
""",
            "safe_code": """
public void listFiles(String directory) throws IOException {
    // ProcessBuilder 사용 및 인자 분리
    ProcessBuilder pb = new ProcessBuilder("ls", directory);
    Process p = pb.start(); // ✅ SAFE
    // ...
}
"""
        }
    ]
}


def process_original_dataset(input_file: str) -> (List[Dict[str, Any]], Set[str]):
    """
    원본 JSON 데이터셋을 로드하고, 필드를 수정한 뒤,
    발견된 CWE 목록을 반환합니다.
    """
    print(f"--- 1. 원본 데이터셋 '{input_file}' 처리 시작 ---")

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"오류: 입력 파일 '{input_file}'을(를) 찾을 수 없습니다.", file=sys.stderr)
        return [], set()
    except json.JSONDecodeError:
        print(f"오류: '{input_file}' 파일의 JSON 형식이 올바르지 않습니다.", file=sys.stderr)
        return [], set()

    processed_data = []
    found_cwes = set()

    for item in data:
        new_item = copy.deepcopy(item)

        # 요구사항 1: 'patched_code' -> 'safe_code' 필드명 변경
        if 'patched_code' in new_item:
            new_item['safe_code'] = new_item.pop('patched_code')

        # 요구사항 2: 'vulnerability_description' 필드 매핑
        description = new_item.get('vulnerability_summary') or new_item.get('cwe_id', 'N/A')
        new_item['vulnerability_description'] = description

        # 데이터셋에 존재하는 CWE ID 수집
        if 'cwe_id' in new_item:
            found_cwes.add(new_item['cwe_id'])

        processed_data.append(new_item)

    print(f"--- 원본 데이터 처리 완료. (총 {len(processed_data)}개)")
    print(f"--- 발견된 CWE ID (고유): {found_cwes} ---")
    return processed_data, found_cwes


def generate_new_examples(cwes_to_generate: Set[str], count_per_cwe: int = 10) -> List[Dict[str, Any]]:
    """
    요청된 CWE 목록을 기반으로 "교과서적인" 일반 예제를 생성합니다.
    """
    print(f"\n--- 2. 일반적인 예제 데이터 생성 시작 (CWE당 {count_per_cwe}개) ---")
    generated_data = []

    # 템플릿이 정의된 CWE에 대해서만 생성
    target_cwes = cwes_to_generate.intersection(CWE_EXAMPLE_TEMPLATES.keys())
    print(f"--- 생성 대상 CWE: {target_cwes} ---")

    for cwe in target_cwes:
        templates = CWE_EXAMPLE_TEMPLATES[cwe]
        print(f"--- '{cwe}' 예제 생성 중...")

        for i in range(count_per_cwe):
            # 템플릿 목록을 순환하며 사용 (예: 10개 생성 시 2개 템플릿 5번씩)
            template = copy.deepcopy(templates[i % len(templates)])

            # 약간의 변형 (예: 변수명 변경)을 주어 고유성 확보
            suffix = f"_{i}"
            vulnerable_code = template['vulnerable_code'].replace("userInput", f"userInput{suffix}")
            vulnerable_code = vulnerable_code.replace(" name ", f" name{suffix} ")

            safe_code = template['safe_code'].replace("userInput", f"userInput{suffix}")
            safe_code = safe_code.replace(" name ", f" name{suffix} ")

            new_example = {
                "vulnerable_code": vulnerable_code,
                "safe_code": safe_code,
                "cwe_id": cwe,
                "vulnerability_summary": f"{template['vulnerability_summary']} (Common Example {i + 1})",
                "vulnerability_description": f"{template['vulnerability_summary']} (Common Example)",
                "source": "Generated by Augmenter"  # 출처 표기
            }
            generated_data.append(new_example)

    print(f"--- 예제 데이터 생성 완료. (총 {len(generated_data)}개) ---")
    return generated_data


def main():
    """
    메인 실행 함수
    """
    INPUT_JSON = "java.json"
    OUTPUT_JSON = "java_processed_with_common_examples.json"
    EXAMPLES_PER_CWE = 10

    # 1. 원본 데이터셋 처리 및 CWE 목록 확보
    processed_original_data, found_cwes = process_original_dataset(INPUT_JSON)

    if not processed_original_data:
        print("오류: 원본 데이터를 처리하지 못했습니다. 스크립트를 종료합니다.")
        return

    # 2. 발견된 CWE 기반으로 일반 예제 생성
    # (CWE_EXAMPLE_TEMPLATES에 정의된 CWE만 생성됨)
    new_examples = generate_new_examples(found_cwes, EXAMPLES_PER_CWE)

    # 3. 원본 데이터와 새 예제 데이터 병합
    combined_data = processed_original_data + new_examples

    # 4. 최종 파일 저장
    try:
        with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
            json.dump(combined_data, f, indent=4, ensure_ascii=False)

        print(f"\n{'=' * 50}")
        print(f"✅ 작업 완료!")
        print(f"원본 {len(processed_original_data)}개 + 생성된 예제 {len(new_examples)}개 = 총 {len(combined_data)}개")
        print(f"결과가 '{OUTPUT_JSON}' 파일에 저장되었습니다.")
        print(f"{'=' * 50}")

    except IOError as e:
        print(f"오류: 최종 파일 '{OUTPUT_JSON}' 저장 중 오류 발생: {e}", file=sys.stderr)


# --- 스크립트 실행 ---
if __name__ == "__main__":
    main()