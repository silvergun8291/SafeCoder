import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Secure AES-GCM Encryption Example
 * 
 * Security Improvements:
 * 1. Removed hard-coded secret key (CWE-798)
 * 2. Uses AES/GCM/NoPadding (CWE-327) - modern authenticated encryption
 * 3. Externalizes secret key via environment variable
 * 4. Uses secure key derivation (16-byte key for AES-128)
 * 5. Includes proper IV/nonce handling
 * 6. Base64 encoding for safe output
 * 7. Comprehensive error handling
 */
public class SecureAESExample {

    // Constants for AES-GCM
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final int AES_KEY_SIZE = 16; // bytes for AES-128

    public static void main(String[] args) {
        try {
            // 1. Retrieve secret key from environment (never hard-coded)
            String base64Key = System.getenv("AES_SECRET_KEY");
            if (base64Key == null || base64Key.length() < 24) { // 16 bytes = 24 base64 chars
                throw new IllegalArgumentException("Invalid or missing AES_SECRET_KEY environment variable");
            }

            // 2. Decode and validate key size
            byte[] decodedKey = Base64.getDecoder().decode(base64Key);
            if (decodedKey.length != AES_KEY_SIZE) {
                throw new IllegalArgumentException("Secret key must be exactly " + AES_KEY_SIZE + " bytes");
            }

            Key key = new SecretKeySpec(decodedKey, "AES");

            // 3. Generate random IV (nonce)
            byte[] iv = new byte[12]; // GCM recommended IV size
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            // 4. Initialize cipher
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);

            // 5. Encrypt data
            String plaintext = "Hello World";
            byte[] encryptedText = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));

            // 6. Output encrypted data + IV (for decryption later)
            System.out.println("Encrypted (Base64): " + Base64.getEncoder().encodeToString(encryptedText));
            System.out.println("IV (Hex): " + HexFormat.of().formatHex(iv));

        } catch (Exception e) {
            System.err.println("Encryption failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}