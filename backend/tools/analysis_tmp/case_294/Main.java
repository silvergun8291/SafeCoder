import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidClassException;
import java.util.Base64;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.nio.file.Files;
import java.nio.file.Paths;

public class SecureClass implements Serializable {
    private static final long serialVersionUID = 1L; // Fixed serial version UID
    private static final Map<String, String[]> ALLOWLISTED_COMMANDS = new HashMap<>();
    private static final Map<String, String> ALLOWLISTED_ARGS = new HashMap<>();
    static {
        ALLOWLISTED_COMMANDS.put("echo", new String[]{"echo", ""}); // Empty placeholder
        ALLOWLISTED_COMMANDS.put("ls", new String[]{"ls", "-l"});
        ALLOWLISTED_COMMANDS.put("cat", new String[]{"cat", "/tmp/allowed.txt"});
        ALLOWLISTED_ARGS.put("echo", ".*"); // Regex for allowed arguments
    }
    private final String commandHash; // Store hash instead of raw command
    private final String[] commandArgs;

    public SecureClass(String command) {
        if (!isCommandAllowed(command, commandArgs = new String[0])) {
            throw new IllegalArgumentException("Command not allowed: " + command);
        }
        this.commandHash = hashCommand(command);
    }

    private boolean isCommandAllowed(String command, String[] commandArgs) {
        if (command == null || command.trim().isEmpty()) {
            return false;
        }
        String[] parts = command.trim().split("\\s+", 2);
        if (parts.length == 0) return false;
        
        String cmd = parts[0];
        String[] template = ALLOWLISTED_COMMANDS.get(cmd);
        if (template == null) return false;
        
        if (parts.length == 1) {
            if (template.length == 1) {
                this.commandArgs = template;
                return true;
            }
            return false;
        }
        
        if (cmd.equals("echo")) {
            String arg = parts[1];
            if (arg.matches(ALLOWLISTED_ARGS.get(cmd))) {
                this.commandArgs = new String[]{template[0], arg};
                return true;
            }
            return false;
        }
        
        return Arrays.equals(template, parts);
    }

    private String hashCommand(String command) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(command.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hashing algorithm not found", e);
        }
    }

    private void executeCommand() {
        try {
            ProcessBuilder pb = new ProcessBuilder();
            String[] safeArgs = new String[commandArgs.length];
            for (int i = 0; i < commandArgs.length; i++) {
                if (i == 1 && commandArgs[0].equals("echo")) {
                    if (!commandArgs[1].matches(ALLOWLISTED_ARGS.get("echo"))) {
                        throw new SecurityException("Argument not allowed: " + commandArgs[1]);
                    }
                }
                safeArgs[i] = commandArgs[i];
            }
            pb.command(safeArgs); // Direct API-based execution with argument array
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            // Read output if needed
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                System.err.println("Command exited with code: " + exitCode);
            }
        } catch (IOException | InterruptedException ex) {
            System.err.println("Command execution failed: " + ex.getMessage());
            Thread.currentThread().interrupt();
        }
    }

    public static void main(String[] args) {
        try (ObjectInputStream in = new ObjectInputStream(
                new FileInputStream("/tmp/userInput.ser"))) {
            
            Object obj = in.readObject();
            if (!(obj instanceof SecureClass)) {
                throw new InvalidClassException(obj.getClass().getName(), "Unexpected class");
            }
            SecureClass secureInstance = (SecureClass) obj;
            
            // Verify file existence and permissions
            if (secureInstance.commandArgs != null && secureInstance.commandArgs.length > 0) {
                if (secureInstance.commandArgs[0].equals("cat") && 
                    secureInstance.commandArgs[1].equals("/tmp/allowed.txt")) {
                    if (!Files.exists(Paths.get("/tmp/allowed.txt")) || 
                        !Files.isReadable(Paths.get("/tmp/allowed.txt"))) {
                        throw new SecurityException("File not accessible: /tmp/allowed.txt");
                    }
                }
            }
            
            // No command reconstruction needed - use stored command args directly
            secureInstance.executeCommand();
        } catch (IOException | ClassNotFoundException i) {
            System.err.println("Deserialization failed: " + i.getMessage());
        }
    }
}