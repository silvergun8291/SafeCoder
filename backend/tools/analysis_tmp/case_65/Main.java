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
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

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
        if (command == null || !ALLOWED_COMMANDS.contains(command)) {
            throw new SecurityException("Command not allowed: " + command);
        }
        
        // 2. Validate arguments (CWE-88 mitigation)
        if (args != null) {
            List<String> validatedArgs = Arrays.stream(args)
                .filter(arg -> arg != null && !arg.isEmpty())
                .filter(arg -> arg.length() <= MAX_INPUT_LENGTH)
                .filter(arg -> !containsInvalidChars(arg))
                .filter(arg -> !arg.startsWith("-") || isValidOption(arg))  // Validate command options
                .collect(Collectors.toList());
            
            if (validatedArgs.size() != args.length) {
                throw new IllegalArgumentException("One or more arguments are invalid");
            }
            
            args = validatedArgs.toArray(new String[0]);
        } else {
            args = new String[0];
        }
        
        // 3. Execute command securely using absolute path and argument array
        List<String> commandList = new java.util.ArrayList<>();
        commandList.add(command);
        if (args != null) {
            commandList.addAll(Arrays.asList(args));
        }
        
        ProcessBuilder processBuilder = new ProcessBuilder(commandList);
        
        // 4. Set secure process environment (no inheritance of parent environment)
        processBuilder.environment().clear();
        processBuilder.environment().put("SECURE_MODE", "true");
        
        // 5. Redirect error stream to capture errors
        processBuilder.redirectErrorStream(true);
        
        // 6. Set working directory to a safe location
        Path safeDir = Paths.get("/tmp");
        if (!Files.isDirectory(safeDir) || !Files.isExecutable(safeDir) || 
            !Files.isReadable(safeDir) || !Files.isWritable(safeDir)) {
            throw new IOException("Safe directory not accessible: " + safeDir);
        }
        processBuilder.directory(safeDir.toFile());
        
        Process process = processBuilder.start();
        
        // 7. Read process output with timeout to prevent resource exhaustion
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                if (output.length() > 1024 * 1024) {  // 1MB limit
                    process.destroyForcibly();
                    throw new IOException("Output size limit exceeded");
                }
                output.append(line).append(System.lineSeparator());
            }
        }
        
        // 8. Wait for process completion with timeout
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("Command timeout: " + command);
        }
        
        int exitCode = process.exitValue();
        if (exitCode != 0) {
            throw new IOException("Command failed with exit code " + exitCode + ": " + command);
        }
        
        return output.toString();
    }
    
    /**
     * Checks if string contains potentially dangerous characters.
     * 
     * @param input The string to check
     * @return true if invalid characters found
     */
    private boolean containsInvalidChars(String input) {
        // Allow alphanumeric, spaces, and common punctuation
        return !input.matches("[a-zA-Z0-9 _\\-\\.\\/]+");
    }
    
    /**
     * Validates command line options to prevent option injection attacks.
     * 
     * @param option The option to validate
     * @return true if option is valid
     */
    private boolean isValidOption(String option) {
        // For /bin/ls, valid options are -a, -l, -t, etc.
        // This should be expanded based on the specific command being executed
        if (option.equals("-a") || option.equals("-l") || option.equals("-t") || 
            option.equals("-d") || option.equals("--color=never")) {
            return true;
        }
        
        // Check for valid numeric options
        if (option.matches("-[0-9]+")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Securely retrieves a secret from environment or secret manager.
     * 
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
            throw new SecurityException("Secret not found: " + secretName);
        }
        
        return secretValue;
    }
    
    public static void main(String[] args) {
        SecureProcessExecutor executor = new SecureProcessExecutor();
        
        try {
            // Example usage - would typically use secrets for command parameters
            String result = executor.executeSecureCommand("/bin/ls", new String[]{"-l", "/tmp"});
            System.out.println("Command output:\n" + result);
            
            // Example secret retrieval
            String apiKey = executor.getSecureSecret("API_KEY");
            System.out.println("API Key retrieved successfully");
        } catch (SecurityException | IllegalArgumentException e) {
            System.err.println("Security error: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("IO error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            // In production, use secure logging framework with proper sanitization
            System.err.println("Stack trace:");
            for (StackTraceElement element : e.getStackTrace()) {
                System.err.println("  at " + element);
            }
        }
    }
}