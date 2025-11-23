import java.sql.*;
import java.util.Properties;
import java.util.Objects;

/**
 * Secure database authentication example with:
 * - Externalized credentials via environment variables
 * - Prepared statements to prevent SQL injection (CWE-89)
 * - Input validation and sanitization
 * - Secure error handling
 * - Connection pooling (recommended in production)
 */
public class SecureAuth {

    // TODO: In production, use a secret manager (e.g., HashiCorp Vault, AWS Secrets Manager)
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydatabase";
    private static final String DB_USER = Objects.requireNonNull(System.getenv("DB_USERNAME"));
    private static final String DB_PASSWORD = Objects.requireNonNull(System.getenv("DB_PASSWORD"));

    public static void main(String[] args) {
        // Simulated user input - in real applications, validate and sanitize all inputs
        String username = "testUser";
        String password = "testPassword";

        // Input validation (basic example - expand based on business rules)
        if (!isValidUsername(username) || !isValidPassword(password)) {
            System.err.println("Invalid input: Username or password does not meet requirements.");
            return;
        }

        try (Connection conn = getSecureConnection();
             PreparedStatement stmt = conn.prepareStatement("SELECT Username FROM Users WHERE Username = ? AND Password = ?")) {

            // Use parameterized queries to prevent SQL injection (CWE-89)
            stmt.setString(1, username);
            stmt.setString(2, hashPassword(password)); // Never store plaintext passwords

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    System.out.println("Authentication successful for user: " + rs.getString("Username"));
                } else {
                    System.out.println("Authentication failed: Invalid credentials");
                }
            }
        } catch (SQLException e) {
            // Log securely (avoid exposing stack traces to users)
            System.err.println("Database error occurred: " + e.getMessage());
            // In production, use a logging framework with proper security handling
        }
    }

    /**
     * Establishes a secure database connection with proper configuration
     * @return Secure database connection
     * @throws SQLException if connection fails
     */
    private static Connection getSecureConnection() throws SQLException {
        Properties props = new Properties();
        props.setProperty("user", DB_USER);
        props.setProperty("password", DB_PASSWORD);
        props.setProperty("useSSL", "true"); // Enable SSL for secure communication
        props.setProperty("requireSSL", "true");
        return DriverManager.getConnection(DB_URL, props);
    }

    /**
     * Validates username format (example policy)
     * @param username Username to validate
     * @return true if valid
     */
    private static boolean isValidUsername(String username) {
        return username != null && username.matches("^[a-zA-Z0-9_]{3,20}$");
    }

    /**
     * Validates password strength (example policy)
     * @param password Password to validate
     * @return true if valid
     */
    private static boolean isValidPassword(String password) {
        return password != null && password.length() >= 12 && 
               password.matches("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#&]).{12,}$");
    }

    /**
     * Hashes password using secure algorithm (PBKDF2 with HMAC-SHA256)
     * @param password Plaintext password
     * @return Hashed password
     */
    private static String hashPassword(String password) {
        // In production, use a proper password hashing library like BCrypt or Argon2
        try {
            // This is a simplified example - real implementation should store salt separately
            java.security.SecureRandom random = new java.security.SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            
            javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory
                .getInstance("PBKDF2WithHmacSHA256");
            javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                password.toCharArray(), salt, 65536, 128);
            byte[] hash = factory.generateSecret(spec).getEncoded();
            
            // Return salt + hash for storage (simplified for example)
            return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Password hashing failed", e);
        }
    }
}