"""
간단한 Diff/AST Diff 출력 스크립트

실행: python print_analysis.py
"""

import sys
from pathlib import Path

# 프로젝트 루트를 sys.path에 추가
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.analyzers import DiffAnalyzer, ASTAnalyzer
import json


# 원본 취약 코드 (raw string 사용)
VULNERABLE_CODE = r"""
import java.sql.*;
import java.io.*;

public class VulnerableApp {
    
    public void executeCommand(String userInput) throws IOException {
      Runtime.getRuntime().exec("ping " + userInput);
    }
    
    public ResultSet getUserData(String userId) throws SQLException {
      Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
      Statement stmt = conn.createStatement();
      String query = "SELECT * FROM users WHERE id = '" + userId + "'";
      return stmt.executeQuery(query);
    }
    
    public void parseXML(String xmlData) throws Exception {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
    }
    
    public String readFile(String filename) throws IOException {
      FileInputStream fis = new FileInputStream("/data/" + filename);
      byte[] data = new byte[fis.available()];
      fis.read(data);
      return new String(data);
    }
}
"""

# 패치된 보안 코드 (raw string 사용)
SECURE_CODE = r"""
import java.io.*;
import java.nio.file.*;
import java.sql.*;
import java.util.regex.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import org.xml.sax.*;

public class SecureApplication {

    private static final Pattern VALID_PING_TARGET = Pattern.compile("^([0-9]{1,3}\\.){3}[0-9]{1,3}|[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*$");
    private static final String PING_COMMAND = "/bin/ping";

    public void executeCommand(String userInput) throws IOException {
        if (userInput == null || !VALID_PING_TARGET.matcher(userInput).matches()) {
            throw new IllegalArgumentException("Invalid ping target: " + userInput);
        }
        ProcessBuilder processBuilder = new ProcessBuilder(PING_COMMAND, "-c", "1", userInput);
        Process process = processBuilder.start();
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IOException("Ping command failed");
        }
    }

    private static final Pattern USER_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_]{1,50}$");

    public ResultSet getUserData(String userId) throws SQLException {
        if (userId == null || !USER_ID_PATTERN.matcher(userId).matches()) {
            throw new IllegalArgumentException("Invalid user ID");
        }
        Connection conn = DriverManager.getConnection(
            System.getenv("DB_URL"),
            System.getenv("DB_USER"),
            System.getenv("DB_PASSWORD")
        );
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        pstmt.setString(1, userId);
        return pstmt.executeQuery();
    }

    public Document parseXML(String xmlData) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xmlData)));
    }

    private static final Pattern VALID_FILENAME = Pattern.compile("^[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)?$");
    private static final Path BASE_DIR = Paths.get("/data");

    public String readFile(String filename) throws IOException {
        if (filename == null || !VALID_FILENAME.matcher(filename).matches()) {
            throw new IllegalArgumentException("Invalid filename");
        }
        Path resolvedPath = BASE_DIR.resolve(filename).normalize();
        if (!resolvedPath.startsWith(BASE_DIR)) {
            throw new IllegalArgumentException("Path traversal detected");
        }
        return new String(Files.readAllBytes(resolvedPath));
    }
}
"""


def main():
    print("=" * 100)
    print("🔧 UNIFIED DIFF 결과")
    print("=" * 100)

    # Diff 분석
    diff_result = DiffAnalyzer.analyze(VULNERABLE_CODE, SECURE_CODE)

    print("\n[Diff Text]")
    print(diff_result['diff_text'])

    print("\n" + "-" * 100)
    print(f"Added Lines: {diff_result['added_lines']}")
    print(f"Removed Lines: {diff_result['removed_lines']}")
    print(f"Total Changed Lines: {diff_result['changed_lines']}")

    print("\n\n" + "=" * 100)
    print("🌳 AST DIFF 결과")
    print("=" * 100)

    # AST 분석
    ast_result = ASTAnalyzer.analyze(VULNERABLE_CODE, SECURE_CODE, "java")

    print("\n[JSON Format]")
    print(json.dumps(ast_result, indent=2, ensure_ascii=False))

    print("\n" + "-" * 100)
    print("[Formatted Output]")
    print(f"\n추가된 Import: {len(ast_result['added_imports'])}개")
    for imp in ast_result['added_imports']:
        print(f"  + {imp}")

    print(f"\n추가된 메서드: {len(ast_result['added_methods'])}개")
    for method in sorted(ast_result['added_methods'])[:20]:  # 최대 20개만
        print(f"  + {method}()")
    if len(ast_result['added_methods']) > 20:
        print(f"  ... 외 {len(ast_result['added_methods']) - 20}개")

    print(f"\n제거된 메서드: {len(ast_result['removed_methods'])}개")
    for method in sorted(ast_result['removed_methods']):
        print(f"  - {method}()")

    print(f"\n타입 변경: {len(ast_result['changed_types'])}개")
    for change in ast_result['changed_types']:
        print(f"  {change['from']} → {change['to']}")

    print(f"\n변수 변경: {len(ast_result['changed_variables'])}개")
    for change in ast_result['changed_variables']:
        print(f"  {change['from']} → {change['to']}")

    print("\n" + "=" * 100)


if __name__ == "__main__":
    main()
