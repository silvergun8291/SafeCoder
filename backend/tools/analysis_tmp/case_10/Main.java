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
     * @return Process output as String
     * @throws IOException If process execution fails
     * @throws SecurityException If command/arguments not allowed
     */
    public String executeSecureCommand(String command, String[] args) throws IOException {
        // Validate command path
        if (!ALLOWED_COMMANDS.contains(command)) {
            throw new SecurityException("Command not allowed: " + command);
        }
        
        // Validate arguments based on command
        if (command.equals("/bin/ls") && args != null) {
            for (String arg : args) {
                if (!ALLOWED_LS_ARGS.contains(arg)) {
                    throw new SecurityException("Argument not allowed for ls: " + arg);
                }
            }
        }
        
        // Get secret from secure source (e.g., environment variable or secret manager)
        String apiKey = getSecureSecret("API_KEY");
        
        // Example of using secret in process environment if needed
        ProcessBuilder processBuilder = new ProcessBuilder(command, args);
        processBuilder.environment().put("API_KEY", apiKey);
        
        // Set secure process configuration
        processBuilder.redirectErrorStream(true);
        processBuilder.inheritIO(false);
        
        Process process = processBuilder.start();
        
        // Read process output securely
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            
            String line;
            StringBuilder output = new StringBuilder();
            
            while ((line = reader.readLine()) != null) {
                output.append(line).append(System.lineSeparator());
            }
            
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IOException("Command failed with exit code: " + exitCode);
            }
            
            return output.toString();
        }
    }
    
    /**
     * Retrieves a secret from a secure source
     * @param secretName Name of the secret to retrieve
     * @return Secret value
     * @throws SecurityException If secret cannot be retrieved
     */
    private String getSecureSecret(String secretName) {
        // In production, use a secret manager like HashiCorp Vault, AWS Secrets Manager, etc.
        // For this example, we use environment variables as a fallback
        String secretValue = System.getenv(secretName);
        
        if (secretValue == null || secretValue.isEmpty()) {
            throw new SecurityException("Required secret not found: " + secretName);
        }
        
        return secretValue;
    }
    
    public static void main(String[] args) {
        SecureProcessExecutor executor = new SecureProcessExecutor();
        
        try {
            // Example usage - would typically get command/args from validated input
            String result = executor.executeSecureCommand("/bin/ls", new String[]{"-l"});
            System.out.println("Command output:");
            System.out.println(result);
        } catch (Exception e) {
            System.err.println("Error executing command: " + e.getMessage());
            e.printStackTrace();
        }
    }
}