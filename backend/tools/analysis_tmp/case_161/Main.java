import java.nio.file.*;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;

/**
 * SecureFileProcessor handles file operations with security best practices
 * Implementation follows OWASP Secure Coding Practices and CWE mitigation guidelines
 */
public class SecureFileProcessor {
    
    // Constants for security validation
    private static final Pattern VALID_FILENAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,255}$");
    private static final String SECURE_TEMP_DIR = "/secure/temp"; // Should be externalized
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final Base64.Encoder URL_SAFE_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final int RANDOM_BYTES_LENGTH = 32;
    
    /**
     * Securely processes a file with input validation and safe operations
     * 
     * @param filename Name of the file to process
     * @param content Content to write to the file
     * @return Base64 encoded hash of the file content if successful
     * @throws SecurityException If input validation fails
     * @throws RuntimeException If file operations fail
     */
    public String processFile(String filename, String content) {
        // Input validation (CWE-20: Improper Input Validation)
        if (filename == null || !VALID_FILENAME_PATTERN.matcher(filename).matches()) {
            throw new SecurityException("Invalid filename: " + filename);
        }
        
        if (content == null || content.isEmpty()) {
            throw new SecurityException("Content cannot be null or empty");
        }
        
        // Use secure random for temporary files (CWE-330: Use of Insecure Randomness)
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[RANDOM_BYTES_LENGTH]; // Increased entropy
        random.nextBytes(randomBytes);
        String safeRandom = URL_SAFE_ENCODER.encodeToString(randomBytes).replace('=', 'a'); // Replace padding
        String tempFileName = safeRandom + "." + filename;
        
        Path tempFilePath = Paths.get(SECURE_TEMP_DIR, tempFileName).normalize();
        
        // Validate path to prevent path traversal (CWE-22: Path Traversal)
        if (!tempFilePath.startsWith(Paths.get(SECURE_TEMP_DIR))) {
            throw new SecurityException("Invalid file path: " + tempFilePath);
        }
        
        try {
            // Secure file writing with atomic operations (CWE-434: Unrestricted Upload of File with Dangerous Type)
            Files.write(tempFilePath, content.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            
            // Set restrictive permissions (CWE-732: Unrestricted File Upload)
            if (Files.getFileAttributeView(tempFilePath, PosixFileAttributeView.class) != null) {
                Files.setPosixFilePermissions(tempFilePath, PosixFilePermissions.fromString("600"));
            }
            
            // Process file securely (example operation)
            String fileHash = calculateSecureHash(tempFilePath);
            
            // Clean up after processing (CWE-55: Missing Cleanup)
            Files.deleteIfExists(tempFilePath);
            
            return fileHash;
        } catch (Exception e) {
            // Clean up on failure (CWE-73: External Control of File Name or Path)
            try {
                Files.deleteIfExists(tempFilePath);
            } catch (Exception deleteException) {
                // Log deletion failure but don't mask original exception
            }
            throw new RuntimeException("File processing failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Calculates a secure hash of file contents
     * 
     * @param filePath Path to the file
     * @return Base64 encoded hash string
     * @throws RuntimeException If hashing fails
     */
    private String calculateSecureHash(Path filePath) {
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            
            try (var inputStream = Files.newInputStream(filePath)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = inputStream.read(buffer)) > 0) {
                    digest.update(buffer, 0, read);
                }
            }
            
            byte[] hashBytes = digest.digest();
            // Use hex encoding for cryptographic hashes to avoid ambiguity
            StringBuilder hexHash = new StringBuilder(2 * hashBytes.length);
            for (byte b : hashBytes) {
                hexHash.append(String.format("%02x", b));
            }
            return hexHash.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash algorithm not available: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new RuntimeException("Error reading file for hashing: " + e.getMessage(), e);
        }
    }
    
    public static void main(String[] args) {
        // Example usage with validation
        SecureFileProcessor processor = new SecureFileProcessor();
        
        // In production, these would come from validated sources
        String safeFilename = "report_2023.txt";
        String safeContent = "This is secure content";
        
        try {
            String hash = processor.processFile(safeFilename, safeContent);
            System.out.println("File processed successfully. Hash: " + hash);
        } catch (Exception e) {
            System.err.println("Error processing file: " + e.getMessage());
        }
    }
}