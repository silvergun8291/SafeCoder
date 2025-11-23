import java.nio.file.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.PosixFileAttributeView;

/**
 * Secure Java Application Template
 * Demonstrates security-by-design principles and defense-in-depth strategy
 */
public class SecureApplication {
    
    // Constants for security parameters
    private static final int MIN_PASSWORD_LENGTH = 12;
    private static final Pattern SAFE_FILENAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,255}$");
    private static final Charset FILE_CHARSET = StandardCharsets.UTF_8;
    private static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    private static final String FILE_OWNER = "appuser"; // Should be configured securely in production
    
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
            Path baseDir = Paths.get("/opt/app/data/");
            Path userPath = Paths.get(userInput);
            Path safePath = baseDir.resolve(userPath).normalize();
            
            if (!safePath.startsWith(baseDir)) {
                throw new SecurityException("Path traversal attempt detected");
            }
            
            // Verify base directory exists and is accessible
            if (!Files.exists(baseDir) || !Files.isDirectory(baseDir) || !Files.isWritable(baseDir)) {
                throw new SecurityException("Base directory not accessible");
            }
            
            // Create secure random data
            byte[] secureToken = generateSecureToken(32);
            
            // Process file securely
            if (!Files.exists(safePath)) {
                Files.createDirectories(safePath.getParent());
                Files.createFile(safePath);
            }
            
            // Write secure token to file with proper encoding
            String encodedToken = Base64.getUrlEncoder().withoutPadding().encodeToString(secureToken);
            byte[] fileContent = encodedToken.getBytes(FILE_CHARSET);
            
            // Set secure file permissions
            if (Files.exists(safePath)) {
                // Set minimal necessary permissions (owner read/write only)
                if (Files.getFileAttributeView(safePath, PosixFileAttributeView.class) != null) {
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")).values().forEach(perm -> {
                        try {
                            Files.setAttribute(safePath, "posix:permissions", perm, LinkOption.NOFOLLOW_LINKS);
                        } catch (IOException e) {
                            // Log permission setting failure but continue
                            System.err.println("Warning: Failed to set file permission: " + e.getMessage());
                        }
                    });
                }
                
                // Set file owner if possible (requires appropriate privileges)
                try {
                    UserPrincipalLookupService lookupService = Files.getFileSystem(safePath).getUserPrincipalLookupService();
                    UserPrincipal ownerPrincipal = lookupService.lookupPrincipalByName(FILE_OWNER);
                    Files.setOwner(safePath, ownerPrincipal);
                } catch (Exception e) {
                    // Log owner setting failure but continue
                    System.err.println("Warning: Failed to set file owner: " + e.getMessage());
                }
            }
            
            Files.write(safePath, fileContent, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);
            
        } catch (NoSuchAlgorithmException e) {
            // Critical security failure - cannot generate secure random data
            System.err.println("FATAL: Secure random algorithm not available: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            // Secure error handling - don't expose stack traces
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }
    
    /**
     * Get secure user input with length validation
     * @param prompt Input prompt
     * @return Validated user input
     */
    private static String getSecureInput(String prompt) {
        try (java.util.Scanner scanner = new java.util.Scanner(System.in)) {
            System.out.print(prompt);
            String input = scanner.nextLine();
            
            if (input == null || input.trim().isEmpty()) {
                throw new IllegalArgumentException("Input cannot be empty");
            }
            
            return input.trim();
        }
    }
    
    /**
     * Generate cryptographically secure random token
     * @param length Desired token length in bytes
     * @return Secure random byte array
     */
    private static byte[] generateSecureToken(int length) throws NoSuchAlgorithmException {
        Objects.requireNonNull(length, "Length cannot be null");
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be positive");
        }
        
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] token = new byte[length];
        random.nextBytes(token);
        return token;
    }
    
    /**
     * Secure configuration retrieval (template)
     * @param key Configuration key
     * @return Configuration value or null if not found
     */
    private static String getSecureConfig(String key) {
        // In production, this would retrieve from:
        // - Environment variables
        // - Vault/secret manager
        // - Encrypted configuration files
        // Never use hard-coded values
        
        String value = System.getenv(key);
        if (value == null || value.isEmpty()) {
            // TODO: Implement proper secret retrieval mechanism
            throw new SecurityException("Missing required configuration: " + key);
        }
        return value;
    }
}