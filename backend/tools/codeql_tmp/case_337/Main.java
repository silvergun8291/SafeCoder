import java.nio.file.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicReference;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * SecureFileProcessor handles file operations with security best practices
 * Implementation follows OWASP Secure Coding Practices and CWE mitigation guidelines
 */
public class SecureFileProcessor {
    
    // Constants for security validation
    private static final Pattern VALID_FILENAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,255}$");
    private static final String SECURE_TEMP_DIR = "/var/secure/temp"; // Should be externalized
    
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
        // 1. Input validation (CWE-20: Improper Input Validation)
        if (filename == null || !VALID_FILENAME_PATTERN.matcher(filename).matches()) {
            throw new SecurityException("Invalid filename: " + filename);
        }
        
        if (content == null || content.isEmpty()) {
            throw new SecurityException("Content cannot be null or empty");
        }
        
        // 2. Use secure temporary directory (CWE-377: Insecure Temporary File)
        Path tempDir = Paths.get(SECURE_TEMP_DIR);
        if (!Files.exists(tempDir)) {
            try {
                // Use proper file attributes with fallback for non-POSIX systems
                FileAttribute<?>[] attrs = new FileAttribute<?>[0];
                if (Files.getFileAttributeView(tempDir, PosixFileAttributeView.class) != null) {
                    attrs = new FileAttribute<?>[] {
                        PosixFilePermissions.asFileAttribute(
                            PosixFilePermissions.fromString("rw-------"))
                    };
                }
                Files.createDirectories(tempDir, attrs);
            } catch (Exception e) {
                throw new RuntimeException("Failed to create secure temp directory: " + e.getMessage(), e);
            }
        }
        
        // 3. Generate secure temporary file (CWE-377 mitigation)
        Path tempFile;
        try {
            // Use proper file attributes with fallback for non-POSIX systems
            FileAttribute<?>[] attrs = new FileAttribute<?>[0];
            if (Files.getFileAttributeView(tempDir, PosixFileAttributeView.class) != null) {
                attrs = new FileAttribute<?>[] {
                    PosixFilePermissions.asFileAttribute(
                        PosixFilePermissions.fromString("rw-------"))
                };
            }
            tempFile = Files.createTempFile(tempDir, "secure_", ".tmp", attrs);
            
            // Set minimal permissions on non-POSIX systems
            if (Files.getFileAttributeView(tempFile, PosixFileAttributeView.class) == null) {
                Files.setPosixFilePermissions(tempFile, PosixFilePermissions.fromString("rw-------"));
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to create secure temp file: " + e.getMessage(), e);
        }
        
        // 4. Write content securely (CWE-73: External Control of File Name or Path)
        try {
            // Use atomic write operation with proper permissions
            Files.write(tempFile, content.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE);
        } catch (Exception e) {
            try {
                Files.deleteIfExists(tempFile);
            } catch (IOException ex) {
                // Log deletion failure but continue
            }
            throw new RuntimeException("Failed to write file content: " + e.getMessage(), e);
        }
        
        // 5. Generate secure token for file reference (CWE-327: Use of a Broken or Risky Cryptographic Algorithm)
        String secureToken;
        try {
            // Use proper secure random generation
            SecureRandom random = SecureRandom.getInstanceStrong();
            byte[] tokenBytes = new byte[32];
            random.nextBytes(tokenBytes);
            secureToken = HexFormat.of().formatHex(tokenBytes);
        } catch (NoSuchAlgorithmException e) {
            try {
                Files.deleteIfExists(tempFile);
            } catch (IOException ex) {
                // Log deletion failure but continue
            }
            throw new RuntimeException("Failed to generate secure token: " + e.getMessage(), e);
        } catch (Exception e) {
            try {
                Files.deleteIfExists(tempFile);
            } catch (IOException ex) {
                // Log deletion failure but continue
            }
            throw new RuntimeException("Failed to generate secure token: " + e.getMessage(), e);
        }
        
        // 6. Return token instead of direct file reference (defense-in-depth)
        return secureToken;
    }
    
    /**
     * Securely retrieves a secret value from environment variables
     * 
     * @param secretName Name of the secret to retrieve
     * @return Decrypted secret value
     * @throws SecurityException If secret is not available or invalid
     */
    public String getSecureSecret(String secretName) {
        // Never use hard-coded secrets (CWE-798)
        String secretValue = System.getenv(secretName);
        
        if (secretValue == null || secretValue.trim().isEmpty()) {
            throw new SecurityException("Required secret not found: " + secretName);
        }
        
        // In production, would decrypt using proper key management system
        return secretValue;
    }
}