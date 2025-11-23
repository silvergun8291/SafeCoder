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
                    arg.matches(".*[/\\\\].*[/\\\\].*")) {  // Prevent path traversal
                    throw new IllegalArgumentException("Invalid argument: " + arg);
                }
            }
        }
        
        // 3. Execute command using absolute path and argument array (CWE-78 mitigation)
        List<String> commandList = args != null ? Arrays.asList((Object[]) ArrayUtils.addAll(new String[]{command}, args)) : Arrays.asList(command);
        ProcessBuilder processBuilder = new ProcessBuilder(commandList);
        
        // 4. Set secure process environment (CWE-22 mitigation)
        processBuilder.environment().clear();  // Start with empty environment
        processBuilder.environment().put("SECURE_MODE", "true");
        
        // 5. Set working directory to a safe location (CWE-22 mitigation)
        processBuilder.directory(Paths.get("/tmp").toFile());
        
        // 6. Redirect error stream to capture errors (CWE-590 mitigation)
        processBuilder.redirectErrorStream(true);
        
        // 7. Disable inheritance of file descriptors (CWE-369 mitigation)
        processBuilder.inheritIO(false);
        
        // 8. Set resource limits (CWE-774 mitigation)
        if (processBuilder.redirectInput() == null) {
            processBuilder.redirectInput(ProcessBuilder.Redirect.DISCARD);
        }
        
        Process process = processBuilder.start();
        
        // 9. Read process output with timeout (CWE-89 mitigation)
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append(System.lineSeparator());
            }
        }
        
        // 10. Wait for process completion with timeout (CWE-362 mitigation)
        boolean completed = process.waitFor();
        if (!completed) {
            process.destroyForcibly();
            throw new IOException("Process timed out");
        }
        
        // 11. Check exit code (CWE-243 mitigation)
        int exitCode = process.exitValue();
        if (exitCode != 0) {
            throw new IOException("Command failed with exit code: " + exitCode);
        }
        
        return output.toString();
    }
    
    /**
     * Retrieves a secret value from environment variables or secret manager.
     * 
     * @param secretName Name of the secret to retrieve
     * @return Secret value
     * @throws SecurityException If secret not found
     */
    public String getSecureSecret(String secretName) throws SecurityException {
        if (secretName == null || secretName.contains("..") || secretName.contains("/")) {
            throw new SecurityException("Invalid secret name: " + secretName);
        }
        
        String secretValue = System.getenv(secretName);
        if (secretValue == null || secretValue.isEmpty()) {
            // In production, use a secret manager like HashiCorp Vault or AWS Secrets Manager
            throw new SecurityException("Secret not found: " + secretName);
        }
        return secretValue;
    }
    
    /**
     * Securely reads a file with size validation.
     * 
     * @param filePath Path to file to read
     * @return File contents
     * @throws IOException If file read fails
     * @throws SecurityException If file size exceeds limit
     */
    public String readSecureFile(String filePath) throws IOException, SecurityException {
        // Validate file path to prevent path traversal (CWE-22 mitigation)
        if (filePath == null || filePath.contains("..") || filePath.startsWith("/")) {
            throw new SecurityException("Invalid file path: " + filePath);
        }
        
        // Resolve path against a safe base directory
        String safeBaseDir = "/safe/base/dir";
        Path baseDir = Paths.get(safeBaseDir).toAbsolutePath().normalize();
        Path requestedPath = Paths.get(filePath);
        Path resolvedPath = baseDir.resolve(requestedPath).normalize();
        
        // Verify resolved path is within base directory
        if (!resolvedPath.startsWith(baseDir)) {
            throw new SecurityException("Path traversal attempt detected: " + filePath);
        }
        
        // Get file size before reading (CWE-125 mitigation)
        if (Files.size(resolvedPath) > 1024 * 1024) {  // 1MB limit
            throw new SecurityException("File too large: " + filePath);
        }
        
        return new String(Files.readAllBytes(resolvedPath));
    }
}

// Utility class for array operations (to avoid using Apache Commons)
class ArrayUtils {
    public static <T> T[] addAll(T[] array1, T[] array2) {
        if (array1 == null || array2 == null) {
            throw new IllegalArgumentException("Arrays must not be null");
        }
        @SuppressWarnings("unchecked")
        T[] result = (T[]) java.lang.reflect.Array.newInstance(
            array1.getClass().getComponentType(),
            array1.length + array2.length);
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }
}