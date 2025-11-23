import java.sql.*;
import java.util.Properties;
import java.util.regex.Pattern;

/**
 * Secure database authentication example with:
 * - PreparedStatement to prevent SQL Injection (CWE-89)
 * - Externalized credentials via environment variables (CWE-798)
 * - Input validation and sanitization
 * - Secure error handling
 * - Connection pooling (recommended in production)
 */
public class SecureAuth {

    // Input validation patterns (OWASP ASVS 6.1.1)
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]{3,20}$");
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,}$");

    public static void main(String[] args) {
        // Simulated user input (in real app, use secure input handling)
        String username = "testUser";  // Should come from validated user input
        String password = "SecureP@ss1";  // Should come from validated user input

        // Validate inputs before processing
        if (!isValidUsername(username) || !isValidPassword(password)) {
            System.err.println("Invalid input: Username or password does not meet security requirements.");
            return;
        }

        // Externalize credentials via environment variables (never hard-code)
        String dbUrl = System.getenv("DB_URL");
        String dbUser = System.getenv("DB_USER");
        String dbPassword = System.getenv("DB_PASSWORD");

        if (dbUrl == null || dbUser == null || dbPassword == null) {
            System.err.println("Critical error: Database credentials not provided in environment variables.");
            return;
        }

        // Use try-with-resources for automatic resource cleanup
        try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPassword)) {
            // Use PreparedStatement to prevent SQL Injection (CWE-89)
            String query = "SELECT * FROM Users WHERE Username = ? AND Password = ?";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                // Set parameters safely
                stmt.setString(1, username);
                stmt.setString(2, hashPassword(password));  // Always store hashed passwords

                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        System.out.println("Authentication successful for user: " + rs.getString("Username"));
                    } else {
                        System.out.println("Authentication failed: Invalid credentials");
                    }
                }
            }
        } catch (SQLException e) {
            // Log securely without exposing stack traces (OWASP Logging Cheat Sheet)
            System.err.println("Database error occurred. Please try again later.");
            // In production, use a secure logging framework to record the full exception
            e.printStackTrace();  // For demo purposes only; replace with proper logging
        }
    }

    /**
     * Validate username format
     */
    private static boolean isValidUsername(String username) {
        return username != null && USERNAME_PATTERN.matcher(username).matches();
    }

    /**
     * Validate password complexity
     */
    private static boolean isValidPassword(String password) {
        return password != null && PASSWORD_PATTERN.matcher(password).matches();
    }

    /**
     * Hash password before storage (use stronger algorithm in production)
     * TODO: Replace with PBKDF2, bcrypt, or Argon2 in production
     */
    private static String hashPassword(String password) {
        // In real applications, use a proper password hashing library
        // This is a placeholder for demonstration purposes only
        return Integer.toHexString(password.hashCode());
    }
}