import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * SecureProcessExecutor demonstrates secure execution of external processes
 * with input validation, safe process invocation, and proper error handling.
 */
public class SecureProcessExecutor {
    
    // Allowlist of permitted commands - should be externalized in production
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(Arrays.asList(
        "ping", "traceroute", "nslookup"
    ));
    
    // Absolute path to command directory - should be configured externally
    private static final String COMMAND_PATH = "/usr/bin";  // Example for Linux
    
    /**
     * Executes a command securely with input validation and safe process execution.
     * 
     * @param command the command to execute
     * @param arguments command arguments
     * @return the command output as a String
     * @throws IOException if an I/O error occurs
     * @throws IllegalArgumentException if command is not allowed
     */
    public String executeCommand(String command, String[] arguments) 
            throws IOException, IllegalArgumentException {
        
        // Input validation - reject null/empty command
        if (command == null || command.trim().isEmpty()) {
            throw new IllegalArgumentException("Command cannot be null or empty");
        }
        
        // Command allowlisting - prevent command injection
        if (!ALLOWED_COMMANDS.contains(command)) {
            throw new IllegalArgumentException("Command not allowed: " + command);
        }
        
        // Argument validation - reject null arguments
        if (arguments == null) {
            throw new IllegalArgumentException("Arguments array cannot be null");
        }
        
        // Validate arguments for command injection attempts
        for (String arg : arguments) {
            if (arg == null || arg.contains(";") || arg.contains("&") || 
                arg.contains("|") || arg.contains("$") || arg.contains("(") || 
                arg.contains(")") || arg.contains("<") || arg.contains(">") || 
                arg.contains("\\") || arg.contains("/")) {
                throw new IllegalArgumentException("Invalid argument: " + arg);
            }
        }
        
        // Build absolute path to command
        String commandPath = COMMAND_PATH + "/" + command;
        
        // Verify command exists and is a regular file before execution
        if (!Files.isRegularFile(Paths.get(commandPath), LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Command not found or is not a regular file: " + commandPath);
        }
        
        // Use ProcessBuilder with absolute path and argument array
        ProcessBuilder processBuilder = new ProcessBuilder(Arrays.asList(commandPath, arguments));
        
        // Set secure process environment (no inheritance)
        processBuilder.environment().clear();
        
        // Set secure process properties
        processBuilder.redirectErrorStream(true);
        processBuilder.inheritIO(false);
        
        // Set working directory to a safe location
        processBuilder.directory(Paths.get("/tmp").toFile());
        
        // Set resource limits (Linux-specific)
        if (System.getProperty("os.name").toLowerCase().contains("linux")) {
            processBuilder.redirectOutput(ProcessBuilder.Redirect.to(new java.io.File("/dev/null")));
            processBuilder.redirectError(ProcessBuilder.Redirect.to(new java.io.File("/dev/null")));
        }
        
        try {
            Process process = processBuilder.start();
            
            // Read command output
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
                throw new IOException("Command failed with exit code: " + exitCode);
            }
            
            return output.toString();
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command execution interrupted", e);
        }
    }
    
    /**
     * Retrieves a secret value from environment or secret manager.
     * In production, this should integrate with a secret management system.
     * 
     * @param secretName the name of the secret to retrieve
     * @return the secret value
     * @throws SecurityException if secret cannot be retrieved
     */
    public String getSecret(String secretName) {
        String secretValue = System.getenv(secretName);
        if (secretValue == null || secretValue.isEmpty()) {
            // In production, use a secret manager like HashiCorp Vault, AWS Secrets Manager, etc.
            throw new SecurityException("Required secret not found: " + secretName);
        }
        return secretValue;
    }
}