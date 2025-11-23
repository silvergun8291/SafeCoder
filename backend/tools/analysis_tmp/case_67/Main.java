import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
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
        
        // Get secret from secure source using privileged action
        String apiKey = AccessController.doPrivileged((PrivilegedAction<String>) () -> {
            return getSecureSecret("API_KEY");
        });
        
        // Create immutable command array with absolute path
        String[] commandArray = new String[args == null ? 1 : args.length + 1];
        commandArray[0] = command;
        if (args != null) {
            System.arraycopy(args, 0, commandArray, 1, args.length);
        }
        
        // Use ProcessBuilder with absolute path and argument array
        ProcessBuilder processBuilder = new ProcessBuilder(commandArray);
        
        // Set minimal environment with only required variables
        Map<String, String> env = new HashMap<>();
        env.put("SECURE_API_KEY", apiKey);
        processBuilder.environment().clear();
        processBuilder.environment().putAll(env);
        
        // Redirect error stream to capture errors
        processBuilder.redirectErrorStream(true);
        
        // Set working directory to a safe location
        processBuilder.directory(Paths.get("/tmp").toFile());
        
        // Set security manager if available
        SecurityManager securityManager = System.getSecurityManager();
        if (securityManager != null) {
            securityManager.checkExec(command);
        }
        
        Process process = processBuilder.start();
        
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
     * Retrieves a secure secret from environment or secret manager
     * @param key The secret key
     * @return The secret value
     * @throws SecurityException If secret not found
     */
    private String getSecureSecret(String key) {
        // In production, use a secret manager like HashiCorp Vault, AWS Secrets Manager, etc.
        String value = System.getenv(key);
        if (value == null || value.isEmpty()) {
            throw new SecurityException("Required secret not found: " + key);
        }
        return value;
    }
    
    public static void main(String[] args) {
        SecureProcessExecutor executor = new SecureProcessExecutor();
        try {
            // Example usage - would typically take inputs from validated source
            String result = executor.executeSecureCommand("/bin/ls", new String[]{"-l"});
            System.out.println("Command output:\n" + result);
        } catch (Exception e) {
            // Avoid exposing stack traces to users
            System.err.println("Error executing command: " + e.getMessage());
        }
    }
}