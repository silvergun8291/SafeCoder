import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class Main {
    // Store hashed passwords with salts instead of plaintext
    private static final Map<String, String> users = new HashMap<>();
    private static final Map<String, byte[]> SALTS = Map.of(
        "admin", "salt123456789012".getBytes(java.nio.charset.StandardCharsets.UTF_8),
        "user1", "saltabcdefghijkl".getBytes(java.nio.charset.StandardCharsets.UTF_8),
        "user2", "salt987654321098".getBytes(java.nio.charset.StandardCharsets.UTF_8)
    );

    public static void main(String[] args) {
        // Add some users with hashed passwords
        try {
            users.put("admin", hashPassword("password", SALTS.get("admin")));
            users.put("user1", hashPassword("password1", SALTS.get("user1")));
            users.put("user2", hashPassword("password2", SALTS.get("user2")));
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Hashing algorithm not available: " + e.getMessage());
            System.exit(1);
        }

        // Get user input (simulated)
        String username = "admin";
        String password = "password";

        // Validate inputs
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            System.out.println("Access denied!");
            return;
        }

        // Validate username against allowlist
        if (!SALTS.containsKey(username)) {
            System.out.println("Access denied!");
            return;
        }

        // Check if the user exists and the password matches
        if (users.containsKey(username)) {
            try {
                String hashedInput = hashPassword(password, SALTS.get(username));
                if (comparePasswords(users.get(username), hashedInput)) {
                    System.out.println("Access granted!");
                } else {
                    System.out.println("Access denied!");
                }
            } catch (NoSuchAlgorithmException e) {
                System.err.println("Hashing algorithm not available: " + e.getMessage());
                System.exit(1);
            }
        } else {
            System.out.println("Access denied!");
        }
    }

    private static String hashPassword(String password, byte[] salt) throws NoSuchAlgorithmException {
        Objects.requireNonNull(password, "Password cannot be null");
        Objects.requireNonNull(salt, "Salt cannot be null");
        
        MessageDigest md = MessageDigest.getInstance("PBKDF2WithHmacSHA256");
        md.reset();
        byte[] hashedBytes = md.digest(password.getBytes(java.nio.charset.StandardCharsets.UTF_8), salt, 65536);
        return Base64.getEncoder().encodeToString(hashedBytes);
    }

    private static boolean comparePasswords(String expected, String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
            expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            actual.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
    }
}