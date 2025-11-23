import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.PrivilegedAction;
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
        if (command == null || !ALLOWED_COMMANDS.contains(command)) {
            throw new SecurityException("Command not allowed: " + command);
        }
        
        // Validate arguments based on command
        if (command.equals("/bin/ls") && args != null) {
            for (String arg : args) {
                if (arg == null || !ALLOWED_LS_ARGS.contains(arg)) {
                    throw new SecurityException("Argument not allowed for ls: " + arg);
                }
            }
        }
        
        // Use ProcessBuilder with absolute path and argument array
        ProcessBuilder processBuilder = new ProcessBuilder(Arrays.asList(command, args));
        
        // Set secure environment (no inheritance)
        processBuilder.environment().clear();
        processBuilder.environment().put("SECURE_MODE", "true");
        
        // Redirect error stream to capture errors
        processBuilder.redirectErrorStream(true);
        
        // Set working directory to a safe location
        processBuilder.directory(Paths.get("/tmp").toFile());
        
        // Validate command existence before execution
        if (!Files.exists(Paths.get(command), LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("Command does not exist: " + command);
        }
        
        // Validate command is executable
        if (!Files.isExecutable(Paths.get(command), LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("Command not executable: " + command);
        }
        
        // Use privileged action to minimize attack surface
        Process process = AccessController.doPrivileged((PrivilegedAction<Process>) () -> {
            try {
                return processBuilder.start();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        
        // Read process output
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
     * Retrieves a secret value from environment or secret manager
     * @param secretName Name of the secret to retrieve
     * @return Secret value
     * @throws SecurityException If secret not found
     */
    public String getSecretValue(String secretName) {
        if (secretName == null || secretName.isEmpty()) {
            throw new SecurityException("Secret name cannot be null or empty");
        }
        
        // Use privileged action to access environment variables securely
        String value = AccessController.doPrivileged((PrivilegedAction<String>) () -> {
            return System.getenv(secretName);
        });
        
        if (value == null || value.isEmpty()) {
            // In production, use a secret manager like HashiCorp Vault or AWS Secrets Manager
            throw new SecurityException("Secret not found: " + secretName);
        }
        return value;
    }
    
    /**
     * Main method for demonstration purposes
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        SecureProcessExecutor executor = new SecureProcessExecutor();
        
        try {
            // Example of secure command execution
            String result = executor.executeSecureCommand("/bin/ls", new String[]{"-l"});
            System.out.println("Command output:\n" + result);
            
            // Example of secret retrieval
            String apiKey = executor.getSecretValue("PRODUCTION_API_KEY");
            System.out.println("API Key retrieved successfully");
        } catch (SecurityException | IOException e) {
            System.err.println("Security error: " + e.getMessage());
            // Avoid printing stack trace in production
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            // Avoid printing stack trace in production
        }
    }
}