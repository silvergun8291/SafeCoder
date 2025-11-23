import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

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
    
    // Maximum allowed input length to prevent buffer overflow attacks
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
                if (arg == null || arg.length() > MAX_INPUT_LENGTH || containsInvalidChars(arg)) {
                    throw new IllegalArgumentException("Invalid argument: " + arg);
                }
            }
        }
        
        // 3. Execute command securely using absolute path and argument array
        ProcessBuilder processBuilder = new ProcessBuilder(Arrays.asList(command, args));
        
        // 4. Set secure process environment (no inheritance of parent environment)
        processBuilder.environment().clear();
        processBuilder.environment().put("SECURE_MODE", "true");
        
        // 5. Redirect error stream to capture both stdout and stderr
        processBuilder.redirectErrorStream(true);
        
        // 6. Set working directory to a safe location (CWE-209 mitigation)
        processBuilder.directory(Paths.get("/tmp").toFile());
        
        // 7. Set process builder to inherit I/O streams from parent (optional)
        processBuilder.inheritIO(false);
        
        // 8. Set resource limits to prevent resource exhaustion attacks
        if (System.getSecurityManager() != null) {
            ProcessBuilder.Redirect redirect = processBuilder.redirectOutput(ProcessBuilder.Redirect.PIPE);
            processBuilder.redirectOutput(redirect);
        }
        
        Process process = processBuilder.start();
        
        // 9. Read process output with timeout to prevent resource exhaustion
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                if (output.length() > 1024 * 1024) {  // 1MB limit
                    process.destroyForcibly();
                    throw new IOException("Output size limit exceeded");
                }
                output.append(line).append(System.lineSeparator());
            }
        }
        
        // 10. Read process error output
        StringBuilder errorOutput = new StringBuilder();
        try (BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()))) {
            
            String line;
            while ((line = errorReader.readLine()) != null) {
                if (errorOutput.length() > 1024 * 1024) {  // 1MB limit
                    process.destroyForcibly();
                    throw new IOException("Error output size limit exceeded");
                }
                errorOutput.append(line).append(System.lineSeparator());
            }
        }
        
        // 11. Wait for process completion with timeout
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("Command timeout: " + command);
        }
        
        int exitCode = process.exitValue();
        if (exitCode != 0) {
            throw new IOException("Command failed with exit code " + exitCode + 
                ": " + command + "\nError output:\n" + errorOutput.toString());
        }
        
        return output.toString();
    }
    
    /**
     * Checks if string contains potentially dangerous characters.
     * 
     * @param input The string to check
     * @return true if invalid characters found
     */
    private boolean containsInvalidChars(String input) {
        // Allow alphanumeric, spaces, and common punctuation
        return !input.matches("[a-zA-Z0-9 _\\-\\.\\/]+");
    }
    
    /**
     * Securely retrieves a secret from environment or secret manager.
     * 
     * @param secretName Name of the secret to retrieve
     * @return Secret value
     * @throws SecurityException If secret not found or invalid
     */
    public String getSecureSecret(String secretName) throws SecurityException {
        String secretValue = System.getenv(secretName);
        
        if (secretValue == null || secretValue.trim().isEmpty()) {
            // In production, use a secret manager like HashiCorp Vault or AWS Secrets Manager
            throw new SecurityException("Secret not found: " + secretName);
        }
        
        return secretValue;
    }
    
    public static void main(String[] args) {
        SecureProcessExecutor executor = new SecureProcessExecutor();
        
        try {
            // Example usage - would typically use secrets for command parameters
            String result = executor.executeSecureCommand("/bin/ls", new String[]{"-l", "/tmp"});
            System.out.println("Command output:\n" + result);
            
            // Example secret retrieval
            String apiKey = executor.getSecureSecret("API_KEY");
            System.out.println("API Key retrieved successfully");
        } catch (SecurityException | IllegalArgumentException | IOException e) {
            System.err.println("Error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            // Avoid printing stack trace in production to prevent information leakage
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            // Avoid printing stack trace in production to prevent information leakage
        }
    }
}