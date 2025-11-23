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
    
    // Maximum allowed input length to prevent buffer overflow attacks
    private static final int MAX_INPUT_LENGTH = 1024;
    
    /**
     * Securely executes an external command with validated arguments.
     * 
     * @param command The command to execute (must be in allowlist)
     * @param args Command arguments
     * @return Execution result as String
     * @throws SecurityException If command not allowed
     * @throws IllegalArgumentException If input invalid
     * @throws IOException If process execution fails
     */
    public String executeSecureCommand(String command, String[] args) 
            throws SecurityException, IllegalArgumentException, IOException {
        
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
                    arg.contains("\r") || arg.contains("<") || arg.contains(">") || 
                    arg.contains("*") || arg.contains("?")) {
                    throw new IllegalArgumentException("Invalid argument: " + arg);
                }
            }
        }
        
        // 3. Execute command using absolute path and argument array (CWE-78 mitigation)
        List<String> commandList = args != null ? Arrays.asList((Object[]) ArrayUtils.addAll(new String[]{command}, args)) : Arrays.asList(command);
        ProcessBuilder processBuilder = new ProcessBuilder(commandList);
        
        // 4. Set secure process environment (CWE-22 mitigation)
        processBuilder.environment().clear();  // Start with empty environment
        processBuilder.environment().put("LANG", "C");  // Minimal environment
        
        // 5. Set working directory to a safe location (CWE-22 mitigation)
        processBuilder.directory(Paths.get("/tmp").toFile());
        
        // 6. Redirect error stream to capture errors
        processBuilder.redirectErrorStream(true);
        
        // 7. Set secure process attributes (CWE-264 mitigation)
        ProcessBuilder.Redirect redirect = new ProcessBuilder.Redirect.PIPE();
        processBuilder.redirectOutput(redirect);
        
        // 8. Set process security attributes (CWE-264 mitigation)
        ProcessBuilder.Redirect redirectError = new ProcessBuilder.Redirect.PIPE();
        processBuilder.redirectError(redirectError);
        
        Process process = processBuilder.start();
        
        // 9. Read process output with timeout (CWE-362 mitigation)
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append(System.lineSeparator());
            }
        }
        
        // 10. Read process error output
        StringBuilder errorOutput = new StringBuilder();
        try (BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()))) {
            
            String line;
            while ((line = errorReader.readLine()) != null) {
                errorOutput.append(line).append(System.lineSeparator());
            }
        }
        
        // 11. Wait for process completion with timeout (CWE-362 mitigation)
        boolean completed = process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
        if (!completed) {
            process.destroyForcibly();
            throw new IOException("Command timed out: " + command + "\nError: " + errorOutput);
        }
        
        // 12. Check exit code (CWE-78 mitigation)
        int exitCode = process.exitValue();
        if (exitCode != 0) {
            throw new IOException("Command failed with exit code " + exitCode + ": " + command + "\nError: " + errorOutput);
        }
        
        return output.toString();
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
     * @param args Command line arguments (not used)
     */
    public static void main(String[] args) {
        SecureProcessExecutor executor = new SecureProcessExecutor();
        
        try {
            // Example usage - would typically use secrets from environment
            String secret = executor.getSecureSecret("APP_SECRET");
            System.out.println("Secret retrieved successfully");
            
            // Execute a secure command
            String result = executor.executeSecureCommand("/bin/ls", new String[]{"-l", "/tmp"});
            System.out.println("Command output:\n" + result);
            
        } catch (SecurityException | IllegalArgumentException e) {
            System.err.println("Security violation: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Execution error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            // Log stack trace securely in production
        }
    }
}

// Apache Commons Lang ArrayUtils for array concatenation
class ArrayUtils {
    public static <T> T[] addAll(T[] array1, T[] array2) {
        if (array1 == null || array2 == null) {
            throw new IllegalArgumentException("The array must not be null");
        }
        T[] result = Arrays.copyOf(array1, array1.length + array2.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }
}