import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeyException;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class UserInfo implements Serializable {
    private static final long serialVersionUID = 1L;
    String username;
    char[] password;
    
    public UserInfo(String username, char[] password) {
        this.username = username;
        this.password = password;
    }
    
    public String getUsername() {
        return username;
    }
    
    public char[] getPassword() {
        return password;
    }
}

public class SecureSerializationExample {
    private static final String KEY_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 12;
    private static final int TAG_LENGTH = 128;
    private static final String ALLOWED_CLASS = "UserInfo";
    private static final String FILE_PATH = "/tmp/user.ser";
    
    private static final byte[] ENCRYPTION_KEY;
    private static final byte[] IV;
    private static final GCMParameterSpec GCM_PARAMS;

    static {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
            kg.init(KEY_SIZE, new SecureRandom());
            SecretKey key = kg.generateKey();
            ENCRYPTION_KEY = key.getEncoded();
            
            SecureRandom random = new SecureRandom();
            IV = new byte[IV_SIZE];
            random.nextBytes(IV);
            
            GCM_PARAMS = new GCMParameterSpec(TAG_LENGTH, IV);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to initialize encryption key", e);
        }
    }

    public static void main(String[] args) {
        try {
            // Validate file path
            Path path = Paths.get(FILE_PATH);
            if (!path.isAbsolute() || !path.startsWith("/tmp")) {
                throw new SecurityException("Invalid file path: " + FILE_PATH);
            }
            
            // Create sensitive data
            UserInfo sensitiveData = new UserInfo("John Doe", "password123".toCharArray());

            // Serialize & encrypt sensitive data
            try (FileOutputStream fileOut = new FileOutputStream(FILE_PATH)) {
                Cipher cipher = getAESCipher(Cipher.ENCRYPT_MODE);
                try (ObjectOutputStream out = new ObjectOutputStream(new CipherOutputStream(fileOut, cipher))) {
                    out.writeObject(sensitiveData);
                }
            }

            System.out.println("Serialized & encrypted data is saved in " + FILE_PATH);

            // Decrypt & deserialize sensitive data
            try (FileInputStream fileIn = new FileInputStream(FILE_PATH)) {
                Cipher decryptionCipher = getAESCipher(Cipher.DECRYPT_MODE);
                try (ObjectInputStream in = new ObjectInputStream(new CipherInputStream(fileIn, decryptionCipher))) {
                    // Validate class before deserialization
                    Class<?> allowedClass = Class.forName(ALLOWED_CLASS);
                    Object obj = in.readObject();
                    if (!allowedClass.isInstance(obj)) {
                        throw new InvalidClassException(allowedClass.getName(), "Unauthorized deserialization attempt");
                    }
                    UserInfo deserializedData = (UserInfo) obj;
                    
                    System.out.println("Deserialized Data...");
                    System.out.println("Username: " + deserializedData.getUsername());
                    System.out.println("Password: " + new String(deserializedData.getPassword()));
                }
            }
        } catch (Exception e) {
            System.err.println("Security error: " + e.getMessage());
            throw e;
        }
    }

    private static Cipher getAESCipher(int mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY, KEY_ALGORITHM);
        
        if (mode == Cipher.ENCRYPT_MODE) {
            cipher.init(mode, keySpec, GCM_PARAMS);
        } else {
            cipher.init(mode, keySpec, GCM_PARAMS);
        }
        return cipher;
    }
}