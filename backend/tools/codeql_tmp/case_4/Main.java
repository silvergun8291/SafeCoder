import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * SecureProcessExecutor demonstrates secure execution of external processes
 * with input validation, safe process invocation, and proper error handling.
 */
public class SecureProcessExecutor {
    
    // Allowlist of permitted commands - must be absolute paths
    private static final Set<String> ALLOWED_COMMANDS = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList(
            "/usr/bin/env", 
            "/usr/bin/printenv"
        ))
    );
    
    // Allowlist of permitted arguments
    private static final Set<String> ALLOWED_ARGUMENTS = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList(
            "HOME", "USER", "PATH"
        ))
    );

    /**
     * Securely executes an external command with validation
     * @param command The command to execute (must be in allowlist)
     * @param arguments Command arguments (must be in allowlist)
     * @return Process output as String
     * @throws IOException If process execution fails
     * @throws SecurityException If command/arguments not allowed
     */
    public String executeSecureCommand(String command, String[] arguments) 
            throws IOException, SecurityException {
        
        // Validate command path - must be absolute and in allowlist
        if (command == null || !command.startsWith("/") || !ALLOWED_COMMANDS.contains(command)) {
            throw new SecurityException("Command not allowed: " + command);
        }
        
        // Validate arguments - must be in allowlist
        if (arguments != null) {
            for (String arg : arguments) {
                if (arg == null || !ALLOWED_ARGUMENTS.contains(arg)) {
                    throw new SecurityException("Argument not allowed: " + arg);
                }
            }
        }
        
        // Create argument array with null check
        String[] safeArguments = (arguments != null) ? arguments : new String[0];
        
        // Use ProcessBuilder with absolute path and argument array
        ProcessBuilder processBuilder = new ProcessBuilder(command, safeArguments);
        
        // Set secure environment - only allow specific variables
        Map<String, String> env = processBuilder.environment();
        env.keySet().retainAll(ALLOWED_ARGUMENTS);
        
        // Redirect error stream to capture errors
        processBuilder.redirectErrorStream(true);
        
        // Set working directory to a safe location
        processBuilder.directory(Paths.get("/tmp").toFile());
        
        // Set process to not inherit IO streams
        processBuilder.inheritIO(false);
        
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
            throw new IOException("Command failed with exit code: " + exitCode + 
                ". Output: " + output.toString());
        }
        
        return output.toString();
    }

    /**
     * Securely retrieves a secret from environment or secret manager
     * @param secretName Name of the secret to retrieve
     * @return Secret value
     * @throws SecurityException If secret not found or invalid
     */
    public String getSecureSecret(String secretName) throws SecurityException {
        if (secretName == null || secretName.trim().isEmpty()) {
            throw new SecurityException("Secret name cannot be null or empty");
        }
        
        String secretValue = System.getenv(secretName);
        
        if (secretValue == null || secretValue.trim().isEmpty()) {
            // In production, use a secret manager like HashiCorp Vault or AWS Secrets Manager
            // This is a placeholder for demonstration purposes only
            throw new SecurityException("Secret not found: " + secretName);
        }
        
        return secretValue;
    }

    /**
     * Main method for demonstration purposes
     * @param args Command line arguments (not used)
     */
    public static void main(String[] args) {
        SecureProcessExecutor executor = new SecureProcessExecutor();
        
        try {
            // Example of secure command execution
            String result = executor.executeSecureCommand("/usr/bin/env", new String[]{"HOME"});
            System.out.println("Command output:");
            System.out.println(result);
            
            // Example of secure secret retrieval
            String apiKey = executor.getSecureSecret("APP_API_KEY");
            System.out.println("API Key retrieved successfully");
            
        } catch (IOException | SecurityException e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}