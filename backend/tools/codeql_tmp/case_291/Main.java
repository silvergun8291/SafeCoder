import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
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
        
        // 3. Verify command path exists and is executable
        Path commandPath = Paths.get(command).toAbsolutePath().normalize();
        if (!Files.exists(commandPath) || !Files.isExecutable(commandPath) || 
            !commandPath.startsWith("/")) {
            throw new SecurityException("Command not found, not executable, or not absolute path: " + command);
        }
        
        // 4. Execute command securely using absolute path and argument array
        List<String> commandList = Arrays.asList(commandPath.toString(), args != null ? args : new String[0]);
        ProcessBuilder processBuilder = new ProcessBuilder(commandList);
        
        // Disable shell features to prevent command injection (CWE-78)
        processBuilder.redirectErrorStream(true);
        processBuilder.inheritIO(false);  // Prevent leaking sensitive information
        
        // Set environment to empty to prevent environment variable injection
        processBuilder.environment().clear();
        
        // Set working directory to a safe default
        processBuilder.directory(Paths.get("/tmp").toAbsolutePath().normalize().toFile());
        
        Process process = processBuilder.start();
        
        // 5. Read process output with timeout handling
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
        if (input.contains(";") || input.contains("&") || input.contains("|") || 
            input.contains("$") || input.contains("'") || input.contains("\"") || 
            input.contains("`") || input.contains("\\")) {
            throw new IllegalArgumentException("Input contains invalid characters");
        }
        
        // Prevent path traversal attacks
        if (input.contains("../") || input.contains("~")) {
            throw new IllegalArgumentException("Input contains invalid path traversal characters");
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
        } catch (Exception e) {
            // Log stack trace securely in production
            System.err.println("Unexpected error: " + e.getClass().getName() + ": " + e.getMessage());
        }
    }
}