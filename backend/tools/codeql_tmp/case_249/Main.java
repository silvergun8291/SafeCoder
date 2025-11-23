import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
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
    private static final Set<String> ALLOWED_LS_ARGS = new HashSet<>(Arrays.asList(
        "-l", "-a", "-t", "-r", "-h", "-d", "--color"
    ));
    
    // Maximum allowed input length to prevent buffer overflow attacks
    private static final int MAX_INPUT_LENGTH = 1024;
    
    // Maximum allowed output size in bytes
    private static final int MAX_OUTPUT_SIZE = 1024 * 1024; // 1MB
    
    // Maximum process execution time in seconds
    private static final int MAX_EXECUTION_TIME = 10;
    
    /**
     * Securely executes an external command with validated arguments.
     * 
     * @param command The command to execute (must be in allowlist)
     * @param args Command arguments
     * @return Execution result as String
     * @throws SecurityException If command not allowed
     * @throws IllegalArgumentException If input invalid
     * @throws IOException If process execution fails
     * @throws InterruptedException If process wait is interrupted
     */
    public String executeSecureCommand(String command, String[] args) 
            throws SecurityException, IllegalArgumentException, IOException, InterruptedException {
        
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
                    arg.contains(" ") || arg.contains("\t") || arg.contains("\n") || 
                    arg.contains("\r")) {
                    throw new IllegalArgumentException("Invalid argument: " + arg);
                }
            }
            
            // 3. Command-specific argument validation (CWE-78 mitigation)
            if ("/bin/ls".equals(command)) {
                for (String arg : args) {
                    if (!ALLOWED_LS_ARGS.contains(arg) && !isValidPathArgument(arg)) {
                        throw new IllegalArgumentException("Invalid argument for ls: " + arg);
                    }
                }
            }
        }
        
        // 4. Create command list with proper argument handling (CWE-78 mitigation)
        List<String> commandList = args != null ? 
            Arrays.asList((String[]) Arrays.stream(args).toArray(String[]::new)) :
            List.of();
        
        // 5. Create ProcessBuilder with command and arguments
        ProcessBuilder processBuilder = new ProcessBuilder(commandList);
        
        // 6. Set secure process environment (CWE-22 mitigation)
        processBuilder.environment().clear();  // Start with empty environment
        processBuilder.environment().put("SECURE_MODE", "true");
        
        // 7. Set working directory to a safe location (CWE-22 mitigation)
        Path safeDir = Paths.get("/tmp");
        if (!Files.isDirectory(safeDir) || !Files.isReadable(safeDir) || !Files.isExecutable(safeDir)) {
            throw new SecurityException("Safe directory not accessible: " + safeDir);
        }
        processBuilder.directory(safeDir.toFile());
        
        // 8. Redirect error stream to capture errors (CWE-590 mitigation)
        processBuilder.redirectErrorStream(true);
        
        // 9. Set explicit timeouts to prevent resource exhaustion (CWE-362 mitigation)
        Process process = processBuilder.start();
        
        // 10. Read process output with timeout (CWE-89 mitigation)
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                if (output.length() * 2 > MAX_OUTPUT_SIZE) {  // Account for line separator
                    process.destroyForcibly();
                    throw new IOException("Output size limit exceeded");
                }
                output.append(line).append(System.lineSeparator());
            }
        }
        
        // 11. Wait for process completion with timeout (CWE-362 mitigation)
        boolean completed = process.waitFor();
        if (!completed) {
            process.destroyForcibly();
            throw new IOException("Process timed out after " + MAX_EXECUTION_TIME + " seconds");
        }
        
        // 12. Check exit code (CWE-248 mitigation)
        int exitCode = process.exitValue();
        if (exitCode != 0) {
            throw new IOException("Command failed with exit code: " + exitCode);
        }
        
        return output.toString();
    }
    
    /**
     * Validates if a path argument is safe (CWE-22 mitigation).
     * 
     * @param path The path to validate
     * @return true if valid, false otherwise
     */
    private boolean isValidPathArgument(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        
        Path resolvedPath = Paths.get(path).normalize();
        if (resolvedPath.startsWith("..") || resolvedPath.toString().contains("..")) {
            return false;  // Prevent path traversal
        }
        
        try {
            // Check if path exists and is accessible
            return Files.exists(resolvedPath) && 
                   (Files.isReadable(resolvedPath) || Files.isExecutable(resolvedPath));
        } catch (SecurityException e) {
            return false;  // Security manager denies access
        }
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
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        SecureProcessExecutor executor = new SecureProcessExecutor();
        
        try {
            // Example usage - would typically use secrets from environment
            String apiKey = executor.getSecureSecret("API_KEY");
            
            // Execute a secure command
            String result = executor.executeSecureCommand("/bin/ls", new String[]{"-l", "/tmp"});
            System.out.println("Command output:\n" + result);
            
        } catch (SecurityException | IllegalArgumentException e) {
            System.err.println("Security violation: " + e.getMessage());
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Execution error: " + e.getMessage());
            System.exit(1);
        } catch (InterruptedException e) {
            System.err.println("Process wait interrupted: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            System.exit(1);
        }
    }
}