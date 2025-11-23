import java.nio.file.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * SecureFileProcessor handles file operations with security best practices
 * Implementation follows OWASP Secure Coding Practices and CWE mitigation guidelines
 */
public class SecureFileProcessor {
    
    // Constants for security validation
    private static final Pattern VALID_FILENAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,255}$");
    private static final String SECURE_TEMP_DIR = "/tmp/secure_app"; // Should be externalized in production
    
    /**
     * Securely processes a file by validating input, creating a secure temporary file,
     * and performing operations with proper error handling
     * 
     * @param filename Name of the file to process
     * @param data Content to write to the file
     * @return Base64 encoded content of the processed file
     * @throws SecurityException If input validation fails
     * @throws RuntimeException If file operations fail
     */
    public String processFile(String filename, String data) {
        // 1. Input validation (CWE-20: Improper Input Validation)
        if (!isValidFilename(filename)) {
            throw new SecurityException("Invalid filename: " + filename);
        }
        
        // 2. Secure temporary file creation (CWE-416: Use After Free)
        Path tempDir = Paths.get(SECURE_TEMP_DIR);
        try {
            Files.createDirectories(tempDir);
            // Set secure directory permissions (POSIX only)
            if (System.getProperty("os.name").toLowerCase().contains("linux") ||
                System.getProperty("os.name").toLowerCase().contains("mac")) {
                ProcessBuilder pb = new ProcessBuilder("chmod", "700", tempDir.toString());
                pb.inheritIO().start().waitFor();
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to create secure temp directory: " + e.getMessage(), e);
        }
        
        // 3. Secure random file name generation (CWE-22: Path Traversal)
        byte[] randomBytes = new byte[32]; // Increased randomness to 256 bits
        new SecureRandom().nextBytes(randomBytes);
        String randomSuffix = HexFormat.of().formatHex(randomBytes); // Using hex instead of base64 for safer filenames
        String safeFilename = filename + "." + randomSuffix;
        Path tempFile = tempDir.resolve(safeFilename).normalize();
        
        // Verify we're still in the temp directory after normalization
        if (!tempFile.startsWith(tempDir.resolve("."))) {
            throw new SecurityException("Generated path traverses outside secure directory");
        }
        
        // 4. File operations with proper error handling (CWE-73: External Control of File Name)
        try {
            // Write data to file with secure permissions (CWE-732: Unrestricted File Upload)
            Files.write(tempFile, data.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            
            // Set secure file permissions (POSIX only)
            if (System.getProperty("os.name").toLowerCase().contains("linux") ||
                System.getProperty("os.name").toLowerCase().contains("mac")) {
                ProcessBuilder pb = new ProcessBuilder("chmod", "600", tempFile.toString());
                pb.inheritIO().start().waitFor();
            }
            
            // Read data back (demonstrating secure file handling)
            byte[] fileBytes = Files.readAllBytes(tempFile);
            
            // 5. Secure encoding (CWE-201: Information Leak)
            String encodedContent = Base64.getEncoder().encodeToString(fileBytes); // Using standard base64 without MIME
            
            // Clean up (CWE-55: Missing Cleanup)
            Files.deleteIfExists(tempFile);
            
            return encodedContent;
            
        } catch (Exception e) {
            // Clean up on failure
            try { Files.deleteIfExists(tempFile); } catch (Exception ignore) {}
            throw new RuntimeException("File operation failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Validates filename against allowlist pattern
     * @param filename File name to validate
     * @return true if valid, false otherwise
     */
    private boolean isValidFilename(String filename) {
        return filename != null && 
               !filename.isEmpty() && 
               VALID_FILENAME_PATTERN.matcher(filename).matches() &&
               !filename.contains("..") &&  // Prevent path traversal (CWE-22)
               !filename.startsWith("/") &&  // Prevent absolute paths
               !filename.endsWith("/") &&    // Prevent directory paths
               !filename.contains("~");      // Prevent home directory references
    }
    
    public static void main(String[] args) {
        // Example usage with secure defaults
        SecureFileProcessor processor = new SecureFileProcessor();
        try {
            String result = processor.processFile("test_file", "Secure content");
            System.out.println("Processed content: " + result);
        } catch (Exception e) {
            System.err.println("Processing failed: " + e.getMessage());
        }
    }
}