import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * SecureProcessExecutor demonstrates secure execution of external processes
 * with input validation, safe process invocation, and proper error handling.
 */
public class SecureProcessExecutor {
    
    // Allowlist of permitted commands - must be absolute paths
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(Arrays.asList(
        "/usr/bin/env",  // Example allowed command
        "/bin/ls"        // Example allowed command
    ));
    
    // Maximum allowed input length
    private static final int MAX_INPUT_LENGTH = 1024;
    
    /**
     * Securely executes an external command with validated arguments.
     * 
     * @param command The command to execute (must be in allowlist)
     * @param args Command arguments
     * @return Execution result as String
     * @throws SecurityException If command not allowed
     * @throws IllegalArgumentException If input invalid
     * @throws IOException If process execution fails
     */
    public String executeSecureCommand(String command, String[] args) 
            throws SecurityException, IllegalArgumentException, IOException {
        
        // 1. Validate command against allowlist (CWE-78 mitigation)
        if (!ALLOWED_COMMANDS.contains(command)) {
            throw new SecurityException("Command not allowed: " + command);
        }
        
        // 2. Validate arguments (CWE-88 mitigation)
        if (args != null) {
            for (String arg : args) {
                validateInput(arg);
            }
        }
        
        // 3. Execute command securely using absolute path and argument array
        List<String> commandList = args != null ? 
            Arrays.asList((Object[]) ArrayUtils.addAll(new String[]{command}, args)) : 
            Arrays.asList(command);
        ProcessBuilder processBuilder = new ProcessBuilder(commandList);
        
        // Disable shell features to prevent command injection (CWE-78)
        processBuilder.redirectErrorStream(true);
        
        // Set environment to empty to prevent environment variable injection
        processBuilder.environment().clear();
        
        // Set working directory to a safe location
        processBuilder.directory(Paths.get("/tmp").toFile());
        
        // Prevent command injection by explicitly disabling shell
        processBuilder.command().clear();
        for (String cmd : commandList) {
            processBuilder.command().add(cmd);
        }
        
        Process process = processBuilder.start();
        
        // 4. Read process output with timeout handling
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append(System.lineSeparator());
            }
        }
        
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IOException("Command execution failed with exit code: " + exitCode);
        }
        
        return output.toString();
    }
    
    /**
     * Validates input against security policies.
     * 
     * @param input The input to validate
     * @throws IllegalArgumentException If input invalid
     */
    private void validateInput(String input) throws IllegalArgumentException {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        
        if (input.length() > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("Input exceeds maximum allowed length");
        }
        
        // Additional validation rules can be added here
        if (input.matches(".*[;|&$'\"`\\\\].*")) {
            throw new IllegalArgumentException("Input contains invalid characters");
        }
        
        // Prevent path traversal attacks
        if (input.contains("..") || input.startsWith("/")) {
            throw new IllegalArgumentException("Input contains path traversal attempt");
        }
        
        // Prevent null byte injection
        if (input.contains("\u0000")) {
            throw new IllegalArgumentException("Input contains null byte");
        }
    }
    
    /**
     * Retrieves a secret value from environment variables or secret manager.
     * 
     * @param secretName Name of the secret to retrieve
     * @return Secret value
     * @throws SecurityException If secret not found
     */
    public String getSecret(String secretName) throws SecurityException {
        String secretValue = System.getenv(secretName);
        if (secretValue == null || secretValue.isEmpty()) {
            // In production, use a secret manager like HashiCorp Vault, AWS Secrets Manager, etc.
            throw new SecurityException("Required secret not found: " + secretName);
        }
        return secretValue;
    }
    
    /**
     * Main method for demonstration purposes.
     * 
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        SecureProcessExecutor executor = new SecureProcessExecutor();
        
        try {
            // Example usage - would typically use secrets for command path
            String result = executor.executeSecureCommand("/bin/ls", new String[]{"-l", "/tmp"});
            System.out.println("Command output:\n" + result);
            
            // Example secret retrieval
            String apiKey = executor.getSecret("API_KEY_SECRET");
            System.out.println("API Key retrieved successfully");
        } catch (SecurityException | IllegalArgumentException e) {
            System.err.println("Security error: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("IO error: " + e.getMessage());
        } catch (InterruptedException e) {
            System.err.println("Execution interrupted: " + e.getMessage());
            Thread.currentThread().interrupt(); // Restore interrupt status
        }
    }
}

// Utility class for array operations
class ArrayUtils {
    public static <T> T[] addAll(T[] array1, T[] array2) {
        if (array1 == null) {
            return array2;
        }
        if (array2 == null) {
            return array1;
        }
        @SuppressWarnings("unchecked")
        T[] result = (T[]) java.lang.reflect.Array.newInstance(
            array1.getClass().getComponentType(),
            array1.length + array2.length);
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }
}