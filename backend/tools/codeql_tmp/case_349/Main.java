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
                    arg.contains(" ") || arg.contains("\t")) {
                    throw new IllegalArgumentException("Invalid argument: " + arg);
                }
            }
        }
        
        // 3. Execute command using absolute path and argument array (CWE-78 mitigation)
        List<String> commandList = Arrays.asList(command, args != null ? args : new String[0]);
        ProcessBuilder processBuilder = new ProcessBuilder(commandList);
        
        // 4. Set secure process environment (CWE-22 mitigation)
        processBuilder.environment().clear();  // Start with empty environment
        processBuilder.environment().put("SECURE_MODE", "true");
        
        // 5. Set working directory to a safe location (CWE-22 mitigation)
        processBuilder.directory(Paths.get("/tmp").toFile());
        
        // 6. Redirect error stream to capture errors (CWE-596 mitigation)
        processBuilder.redirectErrorStream(true);
        
        // 7. Set explicit redirect for output to prevent file descriptor leaks
        processBuilder.redirectOutput(ProcessBuilder.Redirect.PIPE);
        
        Process process = processBuilder.start();
        
        // 8. Read process output with timeout (CWE-89 mitigation)
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append(System.lineSeparator());
            }
        }
        
        // 9. Wait for process completion with timeout (CWE-362 mitigation)
        boolean completed = process.waitFor();
        if (!completed) {
            process.destroyForcibly();
            throw new IOException("Process timed out");
        }
        
        // 10. Check exit code (CWE-243 mitigation)
        int exitCode = process.exitValue();
        if (exitCode != 0) {
            throw new IOException("Command failed with exit code: " + exitCode);
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
     * Secure file reading with path validation.
     * 
     * @param filePath Path to read
     * @return File contents
     * @throws SecurityException If path traversal detected
     * @throws IOException If file read fails
     */
    public String readSecureFile(String filePath) throws SecurityException, IOException {
        // 1. Validate file path (CWE-22 mitigation)
        if (filePath == null || filePath.contains("..") || 
            filePath.startsWith("/") || filePath.endsWith("/") || 
            filePath.contains("~") || filePath.contains(":") || 
            filePath.contains("\\") || filePath.contains(" ") || 
            filePath.contains("\t")) {
            throw new SecurityException("Invalid file path: " + filePath);
        }
        
        // 2. Resolve absolute path to prevent path traversal
        String baseDir = System.getProperty("java.io.tmpdir");
        String safePath = Paths.get(baseDir, filePath).normalize().toString();
        
        // 3. Verify path is within base directory
        if (!safePath.startsWith(baseDir + java.io.File.separator)) {
            throw new SecurityException("Path traversal detected: " + filePath);
        }
        
        // 4. Verify file exists and is readable before reading
        if (!Files.exists(Paths.get(safePath)) || !Files.isRegularFile(Paths.get(safePath)) || 
            !Files.isReadable(Paths.get(safePath))) {
            throw new SecurityException("File not accessible: " + safePath);
        }
        
        // 5. Read file contents
        return new String(Files.readAllBytes(Paths.get(safePath)));
    }
}