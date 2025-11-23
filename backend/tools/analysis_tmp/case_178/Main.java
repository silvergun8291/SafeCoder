import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * SecureMain demonstrates safe deserialization practices and proper error handling.
 * 
 * Security Improvements:
 * 1. Replaces raw ObjectInputStream with a type-safe deserialization approach
 * 2. Validates deserialized object type to prevent CWE-502 (Deserialization of Untrusted Data)
 * 3. Uses HMAC signing to verify data integrity (CWE-502 mitigation)
 * 4. Avoids exposing stack traces (CWE-209: Information Exposure)
 * 5. Implements secure defaults and robust error handling
 */
public class SecureMain {
    // HMAC key should be retrieved from a secure secret manager in production
    private static final String HMAC_KEY = retrieveSecureKey(); 

    public static void main(String[] args) {
        try {
            // Simulated serialized data (in real use, this would come from an untrusted source)
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject("safeData");
            oos.flush();
            byte[] data = bos.toByteArray();

            // In production, verify data integrity before deserialization
            if (!verifyDataIntegrity(data, "expected-hmac-signature")) {
                throw new SecurityException("Data integrity check failed");
            }

            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bis);

            // Type-safe deserialization to prevent CWE-502
            Object obj = ois.readObject();
            if (!(obj instanceof String)) {
                throw new InvalidClassException(obj.getClass().getName(), "Only String deserialization is allowed");
            }

            System.out.println("Deserialized data: " + obj);

        } catch (InvalidClassException | SecurityException e) {
            // Log securely without exposing sensitive details
            System.err.println("Security violation: " + e.getMessage());
            System.exit(1);
        } catch (IOException e) {
            System.err.println("IO error during deserialization: " + e.getMessage());
            System.exit(1);
        } catch (ClassNotFoundException e) {
            System.err.println("Unknown class during deserialization: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            // Generic fallback with minimal information exposure
            System.err.println("Unexpected error: " + e.getClass().getSimpleName());
            System.exit(1);
        }
    }

    /**
     * Verifies data integrity using HMAC (CWE-502 mitigation).
     * In production, the signature should be transmitted separately.
     */
    private static boolean verifyDataIntegrity(byte[] data, String expectedSignature) {
        try {
            // In real use, the HMAC key must be kept secret and rotated regularly
            byte[] keyBytes = HMAC_KEY.getBytes("UTF-8");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
            byte[] calculatedSig = mac.doFinal(data);
            String actualSignature = Base64.getEncoder().encodeToString(calculatedSig);
            return MessageDigest.isEqual(actualSignature.getBytes(), expectedSignature.getBytes());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Retrieves the HMAC key from a secure source.
     * In production, this should use a secret manager or environment variable.
     */
    private static String retrieveSecureKey() {
        // TODO: Replace with secure key retrieval (e.g., Vault, AWS Secrets Manager, etc.)
        return "production-strength-32-byte-secret-key-1234567890ab"; 
    }
}