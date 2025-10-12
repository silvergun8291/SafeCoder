import java.sql.*;
import java.io.*;
import java.util.*;

public class Vulnerable {

    // CWE-89: SQL Injection
    public User getUser(String username) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        Statement stmt = conn.createStatement();
        // 취약: SQL Injection
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        ResultSet rs = stmt.executeQuery(query);
        return new User(rs);
    }

    // CWE-798: Hard-coded Credentials
    private static final String PASSWORD = "admin123";
    private static final String API_KEY = "sk-1234567890abcdef";

    // CWE-78: OS Command Injection
    public void executeCommand(String userInput) throws IOException {
        // 취약: Command Injection
        Runtime.getRuntime().exec("ls " + userInput);
    }

    // CWE-22: Path Traversal
    public String readFile(String filename) throws IOException {
        // 취약: 경로 검증 없음
        BufferedReader br = new BufferedReader(new FileReader("/var/data/" + filename));
        return br.readLine();
    }

    // CWE-327: Weak Cryptography
    public String hashPassword(String password) throws Exception {
        // 취약: MD5 사용
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return Arrays.toString(hash);
    }

    // CWE-502: Deserialization of Untrusted Data
    public Object deserialize(byte[] data) throws Exception {
        // 취약: 신뢰할 수 없는 데이터 역직렬화
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // CWE-330: Weak Random
    public int generateToken() {
        // 취약: Random 사용
        Random rand = new Random();
        return rand.nextInt();
    }
}

class User {
    User(ResultSet rs) {}
}
