import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
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
    
    // Allowlist of permitted arguments for each command
    private static final Set<String> ALLOWED_LS_ARGS = Set.of("-l", "--color=never");
    
    /**
     * Securely executes an external command with validation
     * @param command The command to execute (must be in allowlist)
     * @param args Arguments for the command
     * @return Execution result as String
     * @throws IOException If process execution fails
     * @throws SecurityException If command/arguments not allowed
     */
    public String executeSecureCommand(String command, String[] args) throws IOException, SecurityException {
        // Validate command path
        if (command == null || !ALLOWED_COMMANDS.contains(command)) {
            throw new SecurityException("Command not allowed: " + command);
        }
        
        // Validate arguments based on command
        if (command.equals("/bin/ls")) {
            if (args == null) {
                args = new String[0];  // Default to empty array if null
            }
            
            for (String arg : args) {
                if (arg == null || !ALLOWED_LS_ARGS.contains(arg)) {
                    throw new SecurityException("Argument not allowed for ls: " + arg);
                }
            }
        } else if (args != null) {
            // For other commands, only allow null or empty args array
            for (String arg : args) {
                if (arg != null) {
                    throw new SecurityException("Arguments not allowed for command: " + command);
                }
            }
        }
        
        // ProcessBuilder is preferred over exec() for better security
        ProcessBuilder processBuilder = new ProcessBuilder(Arrays.asList(command, args));
        
        // Disable inheritance of environment variables by default
        processBuilder.environment().clear();
        
        // Set only necessary environment variables
        String apiKey = getSecureSecret("API_KEY");
        if (apiKey != null && !apiKey.isEmpty()) {
            // Mask sensitive data in logs
            String maskedKey = maskSecret(apiKey);
            processBuilder.environment().put("API_KEY", maskedKey);
        }
        
        // Set working directory to a safe default
        processBuilder.directory(Paths.get("/tmp").toFile());
        
        // Redirect error stream to capture both stdout and stderr
        processBuilder.redirectErrorStream(true);
        
        // Create process with minimal privileges
        Process process = processBuilder.start();
        
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IOException("Command execution failed with exit code: " + exitCode);
        }
        
        return output.toString();
    }
    
    /**
     * Retrieves a secret from a secure source
     * @param key The key for the secret
     * @return The secret value or null if not found
     */
    private String getSecureSecret(String key) {
        // In production, use a secret manager or environment variables
        // Example: return SecretManager.getInstance().getSecret(key);
        if (key == null) {
            return null;
        }
        String secret = System.getenv(key);
        if (secret == null || secret.isEmpty()) {
            return null;
        }
        return secret;
    }
    
    /**
     * Masks sensitive data to prevent exposure in logs or error messages
     * @param secret The secret to mask
     * @return Masked version of the secret
     */
    private String maskSecret(String secret) {
        if (secret == null || secret.isEmpty()) {
            return secret;
        }
        int length = secret.length();
        if (length <= 4) {
            return "****";
        }
        StringBuilder masked = new StringBuilder();
        masked.append(secret, 0, 2);
        for (int i = 2; i < length - 2; i++) {
            masked.append('*');
        }
        masked.append(secret, length - 2, length);
        return masked.toString();
    }
    
    public static void main(String[] args) {
        SecureProcessExecutor executor = new SecureProcessExecutor();
        
        try {
            // Example usage - would typically take inputs from user/config
            String result = executor.executeSecureCommand("/bin/ls", new String[]{"-l"});
            System.out.println("Command output:\n" + result);
        } catch (SecurityException e) {
            System.err.println("Security violation: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Execution error: " + e.getMessage());
        } catch (InterruptedException e) {
            System.err.println("Execution interrupted: " + e.getMessage());
            Thread.currentThread().interrupt(); // Restore interrupt status
        }
    }
}