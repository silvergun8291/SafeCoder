import java.io.*;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public class SecureCommandExecutor implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String commandHash;

    public SecureCommandExecutor(String commandHash) {
        this.commandHash = commandHash;
    }

    public String getCommandHash() {
        return commandHash;
    }

    // Allowlist of permitted commands and their arguments
    private static final String[][] ALLOWLISTED_COMMANDS = {
        {"notepad.exe", "C:\\safe\\path\\file.txt"},
        {"cmd.exe", "/c", "echo", "safe message"}
    };

    // Precomputed hashes of allowlisted commands
    private static final Set<String> ALLOWLISTED_HASHES = new HashSet<>();

    static {
        for (String[] cmd : ALLOWLISTED_COMMANDS) {
            ALLOWLISTED_HASHES.add(hashCommand(cmd));
        }
    }

    // Custom ObjectInputStream to restrict deserialization to allowed classes
    private static class SafeObjectInputStream extends ObjectInputStream {
        private static final Set<String> ALLOWED_CLASSES = new HashSet<>();

        static {
            // Only allow deserialization of trusted classes
            ALLOWED_CLASSES.add(SecureCommandExecutor.class.getName());
        }

        public SafeObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            String className = desc.getName();
            if (!ALLOWED_CLASSES.contains(className)) {
                throw new InvalidClassException("Unauthorized deserialization attempt", className);
            }
            return super.resolveClass(desc);
        }
    }

    private void readObject(ObjectInputStream stream) throws Exception {
        stream.defaultReadObject();
        
        // Get command hash from deserialized state (must be validated)
        String commandHash = (String) stream.readObject();
        
        // Validate hash against allowlist
        if (!ALLOWLISTED_HASHES.contains(commandHash)) {
            throw new SecurityException("Command hash not allowed: " + commandHash);
        }
        
        // Find and execute the matching command
        for (String[] allowedCommand : ALLOWLISTED_COMMANDS) {
            if (Objects.equals(hashCommand(allowedCommand), commandHash)) {
                ProcessBuilder pb = new ProcessBuilder(allowedCommand);
                pb.redirectErrorStream(true);
                Process process = pb.start();
                // Optionally handle process output/input
                break;
            }
        }
    }

    // SHA-256 hash function for command arrays
    private static String hashCommand(String[] command) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            for (String part : command) {
                digest.update(part.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            byte[] hashBytes = digest.digest();
            java.math.BigInteger hashInt = new java.math.BigInteger(1, hashBytes);
            return hashInt.toString(16);
        } catch (Exception e) {
            throw new RuntimeException("Hashing failed", e);
        }
    }

    public static void main(String[] args) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            String[] cmd = {"notepad.exe", "C:\\safe\\path\\file.txt"};
            SecureCommandExecutor sce = new SecureCommandExecutor(hashCommand(cmd));
            oos.writeObject(sce);
            oos.flush();

            // Use the safe deserialization stream
            ObjectInputStream ois = new SafeObjectInputStream(new ByteArrayInputStream(bos.toByteArray()));
            sce = (SecureCommandExecutor) ois.readObject();
            ois.close();

            System.out.println("Deserialized command hash: " + sce.getCommandHash());
        } catch (Exception ex) {
            System.out.println("Exception occurred during deserialization: " + ex.toString());
        }
    }
}