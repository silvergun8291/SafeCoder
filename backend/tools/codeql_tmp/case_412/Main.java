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
                if (arg == null || arg.length() > MAX_INPUT_LENGTH || 
                    arg.contains(";") || arg.contains("&") || arg.contains("|") || 
                    arg.contains("'") || arg.contains("\"") || arg.contains("`") || 
                    arg.contains(" ") || arg.contains("\t") || arg.contains("/")) {
                    throw new IllegalArgumentException("Invalid argument: " + arg);
                }
            }
        }
        
        // 3. Execute command using absolute path and argument array (CWE-78 mitigation)
        List<String> commandList = args != null ? Arrays.asList(command, args) : List.of(command);
        
        // 4. Set secure process environment (CWE-22 mitigation)
        ProcessBuilder processBuilder = new ProcessBuilder(commandList);
        processBuilder.environment().clear();  // Start with empty environment
        processBuilder.environment().put("LANG", "C");  // Minimal environment
        
        // 5. Set working directory to a safe location (CWE-22 mitigation)
        processBuilder.directory(Paths.get("/tmp").toFile());
        
        // 6. Redirect error stream to capture errors
        processBuilder.redirectErrorStream(true);
        
        // 7. Set resource limits (CWE-774 mitigation)
        if (System.getSecurityManager() == null) {
            // Security manager not present - consider adding one in production
            System.err.println("Warning: No security manager installed");
        }
        
        Process process = processBuilder.start();
        
        // 8. Read process output with timeout (CWE-362 mitigation)
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append(System.lineSeparator());
            }
        }
        
        // 9. Wait for process completion with timeout (CWE-362 mitigation)
        boolean completed = process.waitFor(10, TimeUnit.SECONDS);
        if (!completed) {
            process.destroyForcibly();
            throw new IOException("Command timed out: " + command);
        }
        
        // 10. Check exit code (CWE-78 mitigation)
        int exitCode = process.exitValue();
        if (exitCode != 0) {
            throw new IOException("Command failed with exit code " + exitCode + ": " + command);
        }
        
        return output.toString();
    }
    
    /**
     * Securely retrieves a secret from environment variables.
     * 
     * @param secretName Name of the secret to retrieve
     * @return Secret value
     * @throws SecurityException If secret not found
     */
    public String getSecureSecret(String secretName) throws SecurityException {
        String secretValue = System.getenv(secretName);
        if (secretValue == null || secretValue.trim().isEmpty()) {
            throw new SecurityException("Required secret not found: " + secretName);
        }
        return secretValue;
    }
    
    /**
     * Main method for demonstration purposes.
     * 
     * @param args Command line arguments (not used)
     */
    public static void main(String[] args) {
        SecureProcessExecutor executor = new SecureProcessExecutor();
        
        try {
            // Example of secure command execution
            String result = executor.executeSecureCommand("/bin/ls", new String[]{"-l", "/tmp"});
            System.out.println("Command output:\n" + result);
            
            // Example of secure secret retrieval
            String apiKey = executor.getSecureSecret("API_SECRET_KEY");
            System.out.println("API key retrieved successfully");
        } catch (SecurityException | IllegalArgumentException e) {
            System.err.println("Security error: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("IO error: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // Restore interrupt status
            System.err.println("Execution interrupted: " + e.getMessage());
        } catch (Exception e) {
            // This catch-all should never be reached due to specific exceptions above
            System.err.println("Critical system error: " + e.getClass().getName() + ": " + e.getMessage());
            // In production, this should trigger an alert and fail securely
        }
    }
}