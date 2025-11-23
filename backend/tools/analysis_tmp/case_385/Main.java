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
        List<String> commandList = Arrays.asList(command);
        if (args != null) {
            commandList.addAll(Arrays.asList(args));
        }
        
        // 4. Create ProcessBuilder with command array (not string)
        ProcessBuilder processBuilder = new ProcessBuilder(commandList.toArray(new String[0]));
        
        // 5. Set secure process environment (no inheritance of parent environment)
        processBuilder.environment().clear();
        processBuilder.environment().put("SECURE_MODE", "true");
        
        // 6. Redirect error stream to capture both stdout and stderr
        processBuilder.redirectErrorStream(true);
        
        // 7. Set working directory to a safe location (CWE-73 mitigation)
        processBuilder.directory(Paths.get("/safe/working/directory").toFile());
        
        // 8. Set process to inherit I/O handles (CWE-319 mitigation)
        processBuilder.inheritIO(false);
        
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
        try (BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()))) {
            
            String line;
            while ((line = errorReader.readLine()) != null) {
                if (output.length() > 1024 * 1024) {  // 1MB limit
                    process.destroyForcibly();
                    throw new IOException("Error output size limit exceeded");
                }
                output.append(line).append(System.lineSeparator());
            }
        }
        
        // 11. Wait for process completion with timeout
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("Command timeout: " + command);
        }
        
        int exitCode = process.exitValue();
        if (exitCode != 0) {
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
     * @throws SecurityException If secret not found or access denied
     */
    public String getSecureSecret(String secretName) throws SecurityException {
        String secretValue = System.getenv(secretName);
        
        if (secretValue == null || secretValue.isEmpty()) {
            // In production, use a secret manager like HashiCorp Vault or AWS Secrets Manager
            throw new SecurityException("Secret not found: " + secretName);
        }
        
        return secretValue;
    }
    
    /**
     * Secure file reading example with path validation.
     * 
     * @param filePath Path to read (must be within allowed directory)
     * @return File contents
     * @throws SecurityException If path traversal attempt detected
     * @throws IOException If file read fails
     */
    public String readSecureFile(String filePath) throws SecurityException, IOException {
        // Normalize path to prevent path traversal (CWE-22 mitigation)
        String normalizedPath = Paths.get(filePath).normalize().toString();
        
        // Validate path doesn't go outside allowed directory
        if (!normalizedPath.startsWith("/allowed/base/directory/")) {
            throw new SecurityException("Path traversal attempt detected: " + filePath);
        }
        
        return new String(Files.readAllBytes(Paths.get(normalizedPath)));
    }
}