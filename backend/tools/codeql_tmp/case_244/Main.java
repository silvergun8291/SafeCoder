import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * SecureFileProcessor handles file operations with security best practices
 * Implementation follows OWASP Secure Coding Practices and CWE mitigation guidelines
 */
public class SecureFileProcessor {
    
    // Constants for security validation
    private static final Pattern VALID_FILENAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,255}$");
    private static final String SECURE_TEMP_DIR = "/secure/temp"; // Should be externalized
    
    /**
     * Securely processes a file by validating input and using safe APIs
     * 
     * @param filename Name of the file to process
     * @param content Content to write to the file
     * @return Base64 encoded hash of the file content
     * @throws SecurityException If input validation fails
     * @throws RuntimeException If file operations fail
     */
    public String processFile(String filename, String content) {
        // 1. Input validation (CWE-20: Improper Input Validation)
        if (!isValidFilename(filename)) {
            throw new SecurityException("Invalid filename: " + filename);
        }
        
        // 2. Secure file path handling (CWE-22: Path Traversal)
        Path safePath = getSecureFilePath(filename);
        
        // 3. Secure file writing (CWE-73: External Control of File Name)
        try {
            // Use secure defaults: CREATE_NEW (fails if exists), TRUNCATE_EXISTING (safe for temp)
            Files.write(safePath, content.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        } catch (Exception e) {
            throw new RuntimeException("File write failed: " + e.getMessage(), e);
        }
        
        // 4. Return secure representation (not actual content)
        return generateSecureHash(content);
    }
    
    /**
     * Validates filename against allowlist pattern
     * 
     * @param filename Filename to validate
     * @return true if valid
     */
    private boolean isValidFilename(String filename) {
        return filename != null && 
               VALID_FILENAME_PATTERN.matcher(filename).matches() &&
               !filename.contains("..") &&  // Prevent path traversal
               !filename.startsWith("/");   // Prevent absolute paths
    }
    
    /**
     * Creates a secure file path in a restricted directory
     * 
     * @param filename Base filename
     * @return Secure Path object
     */
    private Path getSecureFilePath(String filename) {
        try {
            // Use absolute path to prevent PATH traversal attacks
            Path baseDir = Paths.get(SECURE_TEMP_DIR).toAbsolutePath().normalize();
            Path filePath = baseDir.resolve(filename).normalize();
            
            // Ensure the resolved path is within the base directory
            if (!filePath.startsWith(baseDir)) {
                throw new SecurityException("Path traversal attempt detected: " + filename);
            }
            
            return filePath;
        } catch (Exception e) {
            throw new SecurityException("Invalid file path: " + e.getMessage());
        }
    }
    
    /**
     * Generates a secure hash representation of content
     * 
     * @param content Content to hash
     * @return Base64 encoded hash with URL-safe encoding and padding
     */
    private String generateSecureHash(String content) {
        try {
            // Use SHA-256 with proper salting and encoding
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            
            // Combine content with salt using cryptographic hash
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(salt);
            byte[] hashBytes = digest.digest(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            
            // Return salt + hash to allow verification
            byte[] result = new byte[salt.length + hashBytes.length];
            System.arraycopy(salt, 0, result, 0, salt.length);
            System.arraycopy(hashBytes, 0, result, salt.length, hashBytes.length);
            
            // Use URL-safe Base64 encoder with padding to prevent issues with special characters
            return Base64.getUrlEncoder().encodeToString(result) + "==";
        } catch (NoSuchAlgorithmException e) {
            // This should never happen as SHA-256 is a standard algorithm
            throw new RuntimeException("Critical security failure: SHA-256 algorithm not found", e);
        } catch (Exception e) {
            throw new RuntimeException("Hash generation failed: " + e.getMessage(), e);
        }
    }
    
    public static void main(String[] args) {
        SecureFileProcessor processor = new SecureFileProcessor();
        
        // Example usage - in production, inputs would come from controlled sources
        try {
            String result = processor.processFile("test_file.txt", "Secure Content");
            System.out.println("Processing result: " + result);
        } catch (Exception e) {
            System.err.println("Processing failed: " + e.getMessage());
        }
    }
}