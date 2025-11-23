import java.nio.file.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Secure Java Application Template
 * Demonstrates security-by-design principles and defense-in-depth strategy
 */
public class SecureApplication {
    
    // Constants for security parameters
    private static final int MIN_PASSWORD_LENGTH = 12;
    private static final Pattern SAFE_FILENAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,255}$");
    private static final String BASE_DIR = "/opt/app/data/";
    private static final Charset FILE_ENCODING = StandardCharsets.UTF_8;
    private static final Base64.Encoder URL_SAFE_ENCODER = Base64.getUrlEncoder();
    
    /**
     * Main application entry point
     * @param args Command line arguments (not used in this template)
     */
    public static void main(String[] args) {
        try {
            // Example of secure input handling
            String userInput = getSecureInput("Enter filename: ");
            
            // Validate input against allowlist
            if (!SAFE_FILENAME_PATTERN.matcher(userInput).matches()) {
                throw new IllegalArgumentException("Invalid filename format");
            }
            
            // Example of secure file operation
            Path basePath = Paths.get(BASE_DIR).toAbsolutePath().normalize();
            Path userPath = Paths.get(userInput);
            Path safePath = basePath.resolve(userPath).normalize();
            
            if (!safePath.startsWith(basePath)) {
                throw new SecurityException("Path traversal attempt detected");
            }
            
            // Create secure random data
            byte[] secureToken = generateSecureToken(32);
            
            // Process file securely
            if (!Files.exists(safePath)) {
                Files.createDirectories(safePath.getParent());
                Files.createFile(safePath);
            }
            
            // Write secure data to file with proper encoding
            String encodedToken = URL_SAFE_ENCODER.encodeToString(secureToken);
            byte[] fileContent = encodedToken.getBytes(FILE_ENCODING);
            Files.write(safePath, fileContent, StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            
        } catch (Exception e) {
            // Secure error handling - don't expose stack traces
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }
    
    /**
     * Generate a cryptographically secure random token
     * @param length Number of bytes to generate
     * @return Secure random byte array
     */
    private static byte[] generateSecureToken(int length) {
        try {
            SecureRandom random = SecureRandom.getInstanceStrong();
            byte[] token = new byte[length];
            random.nextBytes(token);
            return token;
        } catch (Exception e) {
            throw new SecurityException("Failed to generate secure random token", e);
        }
    }
    
    /**
     * Secure input handling with length validation
     * @param prompt Input prompt
     * @return Validated user input
     */
    private static String getSecureInput(String prompt) {
        try {
            // In real applications, use secure input methods appropriate to the environment
            System.out.print(prompt);
            java.util.Scanner scanner = new java.util.Scanner(System.in);
            String input = scanner.nextLine();
            
            // Validate input length
            if (input.length() > 1024) {  // Arbitrary but reasonable limit
                throw new IllegalArgumentException("Input exceeds maximum allowed length");
            }
            
            return input;
        } catch (Exception e) {
            throw new SecurityException("Error reading input: " + e.getMessage(), e);
        }
    }
    
    /**
     * Validate password strength
     * @param password Password to validate
     * @return true if password meets security requirements
     */
    public static boolean isPasswordStrong(String password) {
        if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
            return false;
        }
        
        // Additional password complexity checks could be added here
        // This is a minimal example - real applications should use more comprehensive checks
        int requirementCount = 0;
        if (password.matches(".*[0-9].*")) requirementCount++;
        if (password.matches(".*[a-z].*")) requirementCount++;
        if (password.matches(".*[A-Z].*")) requirementCount++;
        if (password.matches(".*[^a-zA-Z0-9].*")) requirementCount++;
        
        return requirementCount >= 3;
    }
}