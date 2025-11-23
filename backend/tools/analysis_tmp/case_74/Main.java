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
    public String executeSecureCommand(String command, String[] args) throws IOException {
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
            // For other commands, no arguments allowed by default
            throw new SecurityException("No arguments allowed for command: " + command);
        }
        
        // Create argument array with null check
        List<String> commandArgs = args != null ? Arrays.asList(args) : List.of();
        
        // Use ProcessBuilder with absolute path and argument array
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.command().addAll(commandArgs);
        
        // Set secure environment - minimal environment only
        processBuilder.environment().clear();  // Start with empty environment
        processBuilder.environment().put("LANG", "C");  // Minimal required environment
        
        // Set working directory to safe location
        processBuilder.directory(Paths.get("/tmp").toFile());
        
        // Redirect error stream to capture both stdout and stderr
        processBuilder.redirectErrorStream(true);
        
        // Create process with minimal permissions
        Process process = processBuilder.start();
        
        // Read process output
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
     * Securely retrieves a secret from environment or secret manager
     * @param secretName Name of the secret to retrieve
     * @return Secret value
     * @throws SecurityException If secret not found
     */
    public String getSecureSecret(String secretName) {
        if (secretName == null || secretName.isEmpty()) {
            throw new SecurityException("Secret name cannot be null or empty");
        }
        
        String secretValue = System.getenv(secretName);
        if (secretValue == null || secretValue.isEmpty()) {
            // In production, use a secret manager like HashiCorp Vault, AWS Secrets Manager, etc.
            throw new SecurityException("Required secret not found: " + secretName);
        }
        return secretValue;
    }
    
    /**
     * Main method for demonstration purposes
     * @param args Command line arguments
     */
    public static void main(String args[]) {
        SecureProcessExecutor executor = new SecureProcessExecutor();
        
        try {
            // Example of secure command execution
            String result = executor.executeSecureCommand("/bin/ls", new String[]{"-l"});
            System.out.println("Command output:");
            System.out.println(result);
            
            // Example of secure secret retrieval
            String apiKey = executor.getSecureSecret("MY_APP_API_KEY");
            System.out.println("API Key retrieved successfully (masked): " + maskSecret(apiKey));
        } catch (SecurityException | IOException e) {
            System.err.println("Security error: " + e.getMessage());
            // Avoid printing stack trace in production
            System.err.println("Error code: " + (e instanceof SecurityException ? 403 : 500));
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            System.err.println("Error code: 500");
            // Log full stack trace in production with proper logging framework
        }
    }
    
    /**
     * Masks secret values in logs/output
     * @param secret The secret to mask
     * @return Masked secret
     */
    private static String maskSecret(String secret) {
        if (secret == null) return null;
        if (secret.length() <= 4) return "****";
        return secret.substring(0, 2) + "**" + secret.substring(secret.length() - 2);
    }
}