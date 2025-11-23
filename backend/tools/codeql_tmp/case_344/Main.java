import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Secure Java Utility Class
 * Demonstrates security best practices for:
 * - Input validation
 * - Secure random generation
 * - Safe file operations
 * - Secure string handling
 */
public class SecureUtils {
    
    // Constants for input validation
    private static final Pattern SAFE_FILENAME_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]+$");
    private static final int MAX_FILENAME_LENGTH = 255;
    private static final int MIN_TOKEN_LENGTH = 16;  // Minimum recommended token length
    private static final int MAX_TOKEN_LENGTH = 1024; // Maximum token length
    private static final String URL_SAFE_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    
    // Secure random number generator
    private static final SecureRandom secureRandom = new SecureRandom();
    
    /**
     * Generate a secure random token
     * @param length desired token length in bytes
     * @return Base64 encoded secure token
     * @throws IllegalArgumentException if length is invalid
     */
    public static String generateSecureToken(int length) {
        if (length <= 0 || length < MIN_TOKEN_LENGTH || length > MAX_TOKEN_LENGTH) {
            throw new IllegalArgumentException("Token length must be between " + MIN_TOKEN_LENGTH + " and " + MAX_TOKEN_LENGTH + " bytes");
        }
        
        byte[] randomBytes = new byte[length];
        secureRandom.nextBytes(randomBytes);
        
        // Use a custom Base64 encoder to ensure URL-safe output without padding
        Base64.Encoder urlEncoder = Base64.getUrlEncoder();
        String encoded = urlEncoder.encodeToString(randomBytes);
        
        // Remove padding characters
        encoded = encoded.replace("=", "");
        
        // Verify all characters are in the URL-safe alphabet
        for (char c : encoded.toCharArray()) {
            if (URL_SAFE_BASE64_ALPHABET.indexOf(c) == -1) {
                throw new SecurityException("Base64 encoding contains unsafe characters: " + c);
            }
        }
        
        return encoded;
    }
    
    /**
     * Validate and sanitize a filename
     * @param filename user-provided filename
     * @return sanitized filename
     * @throws IllegalArgumentException if filename is invalid
     */
    public static String validateFilename(String filename) {
        if (filename == null || filename.length() > MAX_FILENAME_LENGTH || 
            !SAFE_FILENAME_PATTERN.matcher(filename).matches()) {
            throw new IllegalArgumentException("Invalid filename: " + filename);
        }
        return filename;
    }
    
    /**
     * Securely read file contents
     * @param filename validated filename to read
     * @return file contents as String
     * @throws SecurityException if file access is denied
     */
    public static String readFileSecurely(String filename) throws SecurityException {
        try {
            Path path = Paths.get(filename).toAbsolutePath().normalize();
            
            // Prevent path traversal attacks
            if (!path.startsWith(path.getRoot())) {
                throw new SecurityException("Path traversal attempt detected");
            }
            
            // Check if file exists and is readable
            if (!Files.exists(path) || !Files.isRegularFile(path) || !Files.isReadable(path)) {
                throw new SecurityException("File does not exist or is not readable: " + path);
            }
            
            // Read file with proper error handling
            return new String(Files.readAllBytes(path), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new SecurityException("File read error: " + e.getMessage(), e);
        }
    }
    
    /**
     * Securely compare strings to prevent timing attacks
     * @param a first string
     * @param b second string
     * @return true if strings are equal
     */
    public static boolean secureCompare(String a, String b) {
        if (a == b) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        try {
            return MessageDigest.isEqual(a.getBytes(java.nio.charset.StandardCharsets.UTF_8), 
                                        b.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            // This should never happen with the standard UTF-8 charset
            throw new RuntimeException("UTF-8 charset not available", e);
        }
    }
    
    /**
     * Get a secret value from environment variables
     * @param key environment variable key
     * @return secret value
     * @throws SecurityException if secret not found
     */
    public static String getSecret(String key) {
        if (key == null || key.trim().isEmpty()) {
            throw new SecurityException("Secret key cannot be null or empty");
        }
        
        String value = System.getenv(key);
        if (value == null || value.trim().isEmpty()) {
            throw new SecurityException("Missing required secret: " + key);
        }
        return value;
    }
}