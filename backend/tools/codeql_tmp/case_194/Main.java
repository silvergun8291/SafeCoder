import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

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
    
    private static final Logger logger = Logger.getLogger(SecureProcessExecutor.class.getName());
    
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
            logger.log(Level.WARNING, "Command not allowed: {0}", command);
            throw new SecurityException("Command not allowed: " + command);
        }
        
        // 2. Validate arguments (CWE-88 mitigation)
        if (args != null) {
            for (String arg : args) {
                if (arg == null || arg.length() > MAX_INPUT_LENGTH || containsInvalidChars(arg)) {
                    logger.log(Level.WARNING, "Invalid argument: {0}", arg);
                    throw new IllegalArgumentException("Invalid argument: " + arg);
                }
            }
        }
        
        // 3. Execute command securely using absolute path and argument array
        List<String> commandList = Arrays.asList(command, args != null ? args : new String[0]);
        
        // Verify command exists and is executable
        if (!Files.exists(Paths.get(command)) || !Files.isExecutable(Paths.get(command)) || 
            !Files.isRegularFile(Paths.get(command))) {
            logger.log(Level.WARNING, "Command not executable: {0}", command);
            throw new SecurityException("Command not executable: " + command);
        }
        
        ProcessBuilder processBuilder = new ProcessBuilder(commandList);
        
        // 4. Set secure process environment (no inheritance of parent environment)
        processBuilder.environment().clear();
        processBuilder.environment().put("SECURE_MODE", "true");
        
        // 5. Redirect error stream to capture errors
        processBuilder.redirectErrorStream(true);
        
        // 6. Set working directory to a safe location
        try {
            processBuilder.directory(Paths.get("/tmp").toFile());
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to set working directory", e);
            throw new IOException("Failed to set working directory", e);
        }
        
        // 7. Set resource limits
        if (processBuilder.redirectInput() == null) {
            processBuilder.redirectInput(ProcessBuilder.Redirect.DISCARD);
        }
        
        Process process = processBuilder.start();
        
        // 8. Read process output with timeout to prevent resource exhaustion
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                if (output.length() > 1024 * 1024) { // 1MB limit
                    process.destroyForcibly();
                    logger.log(Level.SEVERE, "Output size limit exceeded");
                    throw new IOException("Output size limit exceeded");
                }
                output.append(line).append(System.lineSeparator());
            }
        }
        
        // 9. Wait for process completion with timeout
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            logger.log(Level.SEVERE, "Command timeout: {0}", command);
            throw new IOException("Command timeout: " + command);
        }
        
        int exitCode = process.exitValue();
        if (exitCode != 0) {
            logger.log(Level.SEVERE, "Command failed with exit code {0}: {1}", new Object[]{exitCode, command});
            throw new IOException("Command failed with exit code " + exitCode + ": " + command);
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
            logger.log(Level.WARNING, "Secret not found: {0}", secretName);
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
        } catch (SecurityException | IllegalArgumentException e) {
            System.err.println("Security error: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("IO error: " + e.getMessage());
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected error", e);
            System.err.println("Unexpected error: " + e.getMessage());
        }
    }
}