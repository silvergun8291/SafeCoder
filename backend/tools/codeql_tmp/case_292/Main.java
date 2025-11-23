import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

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
     * @param command the command to execute (e.g., "ping")
     * @param arguments command arguments
     * @return execution result as String
     * @throws IOException if an I/O error occurs
     * @throws IllegalArgumentException if command is not allowed
     */
    public String executeCommand(String command, String[] arguments) 
            throws IOException, IllegalArgumentException {
        
        // 1. Input validation - CWE-20: Improper Input Validation
        if (command == null || !ALLOWED_COMMANDS.contains(command.trim())) {
            throw new IllegalArgumentException("Command not allowed: " + command);
        }
        
        if (arguments == null) {
            throw new IllegalArgumentException("Arguments cannot be null");
        }
        
        // 2. Validate arguments for dangerous patterns - CWE-78: OS Command Injection
        for (String arg : arguments) {
            if (arg == null || !arg.matches("[a-zA-Z0-9.-_]+")) {
                throw new IllegalArgumentException("Invalid argument: " + arg);
            }
        }
        
        // 3. Construct absolute path to command - CWE-426: Untrusted Search Path
        String commandPath = COMMAND_PATH + "/" + command;
        
        if (!Files.exists(Paths.get(commandPath)) || 
            !Files.isRegularFile(Paths.get(commandPath), LinkOption.NOFOLLOW_LINKS) || 
            !Files.isExecutable(Paths.get(commandPath))) {
            throw new IOException("Command not found or not executable: " + commandPath);
        }
        
        // 4. Use ProcessBuilder with argument array - CWE-78: OS Command Injection
        ProcessBuilder processBuilder = new ProcessBuilder(Arrays.asList(commandPath, arguments));
        
        // 5. Set secure process environment - CWE-319: Cleartext Transmission of Sensitive Information
        processBuilder.environment().clear();  // Start with empty environment
        processBuilder.environment().put("LANG", "C");  // Minimal required environment
        
        // 6. Redirect error stream to capture errors - CWE-312: Cleartext Storage of Sensitive Information
        processBuilder.redirectErrorStream(true);
        
        // 7. Set working directory to a safe location - CWE-36: Weak Protection of File Permissions
        processBuilder.directory(Paths.get("/").toAbsolutePath().normalize().toFile());
        
        Process process = processBuilder.start();
        
        // 8. Read process output with timeout - CWE-89: Improper Sanitization of Special Elements
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append(System.lineSeparator());
            }
        }
        
        // 9. Wait for process completion with timeout - CWE-362: Concurrent Execution using Shared Resource
        try {
            if (!process.waitFor(30, TimeUnit.SECONDS)) {  // 30 second timeout
                process.destroyForcibly();
                throw new IOException("Command timed out: " + command);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new IOException("Command interrupted: " + command, e);
        }
        
        int exitCode = process.exitValue();
        if (exitCode != 0) {
            throw new IOException("Command failed with exit code " + exitCode + ": " + command);
        }
        
        return output.toString();
    }
    
    /**
     * Retrieves a secret value from environment or secret manager.
     * 
     * @param secretName name of the secret to retrieve
     * @return secret value
     * @throws SecurityException if secret cannot be retrieved
     */
    public String getSecret(String secretName) {
        String value = System.getenv(secretName);
        if (value == null || value.isEmpty()) {
            // In production, use a secret manager like HashiCorp Vault, AWS Secrets Manager, etc.
            throw new SecurityException("Secret not found: " + secretName);
        }
        return value;
    }
}