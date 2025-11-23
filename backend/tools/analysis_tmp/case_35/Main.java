import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * SecureProcessExecutor demonstrates secure execution of external processes
 * with input validation, safe process invocation, and proper error handling.
 */
public class SecureProcessExecutor {
    
    // Allowlist of permitted commands - must be absolute paths
    private static final Set<String> ALLOWED_COMMANDS = Set.of(
        "/usr/bin/env", 
        "/bin/ls", 
        "/usr/bin/date"
    );
    
    // Allowlist of permitted arguments for each command
    private static final Set<String> ALLOWED_LS_ARGS = Set.of("-l", "--color=never");
    private static final Set<String> ALLOWED_DATE_ARGS = Set.of("+%Y-%m-%d");
    
    /**
     * Securely executes an external command with validation
     * @param command The command to execute (must be in allowlist)
     * @param args Arguments for the command (must be in allowlist for the command)
     * @return Execution result as String
     * @throws IOException If command execution fails
     * @throws IllegalArgumentException If command/args not allowed
     */
    public String executeCommand(String command, String[] args) throws IOException {
        // Validate command path
        if (command == null || !ALLOWED_COMMANDS.contains(command)) {
            throw new IllegalArgumentException("Command not allowed: " + command);
        }
        
        // Validate arguments based on command
        Set<String> allowedArgs = switch (command) {
            case "/bin/ls" -> ALLOWED_LS_ARGS;
            case "/usr/bin/date" -> ALLOWED_DATE_ARGS;
            default -> Set.of(); // No args allowed for other commands
        };
        
        if (args != null) {
            for (String arg : args) {
                if (arg == null || !allowedArgs.contains(arg)) {
                    throw new IllegalArgumentException("Argument not allowed: " + arg);
                }
            }
        }
        
        // Use ProcessBuilder with absolute path and argument array
        ProcessBuilder processBuilder = new ProcessBuilder(command, args != null ? args : new String[0]);
        
        // Set secure process environment (no inheritance)
        processBuilder.environment().clear();
        processBuilder.environment().put("LANG", "C");
        
        // Set working directory to a safe location
        processBuilder.directory(Paths.get("/tmp").toFile());
        
        // Redirect error stream to capture both stdout and stderr
        processBuilder.redirectErrorStream(true);
        
        // Create process with minimal permissions
        Process process = processBuilder.start();
        
        // Read process output with timeout
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            char[] buffer = new char[1024];
            int bytesRead;
            long startTime = System.currentTimeMillis();
            final long timeout = 5000; // 5 seconds timeout
            
            while ((bytesRead = reader.read(buffer)) > 0 && 
                   System.currentTimeMillis() - startTime < timeout) {
                output.append(buffer, 0, bytesRead);
            }
            
            if (System.currentTimeMillis() - startTime >= timeout) {
                process.destroyForcibly();
                throw new IOException("Command execution timed out");
            }
        }
        
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IOException("Command failed with exit code: " + exitCode + 
                ". Output: " + output.toString());
        }
        
        return output.toString();
    }
    
    /**
     * Securely retrieves a secret from environment or secret manager
     * @param secretName Name of the secret to retrieve
     * @return Secret value
     * @throws SecurityException If secret not found or access denied
     */
    public String getSecret(String secretName) {
        if (secretName == null || secretName.isBlank()) {
            throw new SecurityException("Secret name cannot be null or blank");
        }
        
        String value = System.getenv(secretName);
        if (value == null || value.isBlank()) {
            // In production, use a secret manager like HashiCorp Vault, AWS Secrets Manager, etc.
            throw new SecurityException("Secret not found: " + secretName);
        }
        return value;
    }
    
    /**
     * Main method for demonstration purposes
     * @param args Command line arguments (not used)
     */
    public static void main(String[] args) {
        SecureProcessExecutor executor = new SecureProcessExecutor();
        
        try {
            // Example of secure command execution
            String result = executor.executeCommand("/bin/ls", new String[]{"-l"});
            System.out.println("Command output:");
            System.out.println(result);
            
            // Example of secure secret retrieval
            String apiKey = executor.getSecret("API_KEY");
            System.out.println("API Key retrieved successfully (masked): " + maskSecret(apiKey));
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            // Avoid printing stack trace in production
        }
    }
    
    /**
     * Masks secret values in logs/output
     * @param secret The secret to mask
     * @return Masked secret
     */
    private static String maskSecret(String secret) {
        if (secret == null) return null;
        if (secret.length() <= 4) return "XXXX";
        return secret.charAt(0) + "XXX".repeat(Math.max(0, secret.length() - 2)) + secret.charAt(secret.length() - 1);
    }
}