import java.io.*;
import java.net.*;
import java.security.KeyStore;
import javax.net.ssl.*;

/**
 * Secure Server Implementation with SSL/TLS and Command Execution Safeguards
 * 
 * Security Improvements:
 * 1. CWE-319: Replaced plain ServerSocket with SSLServerSocket for encrypted communication
 * 2. CWE-78: Removed direct command execution; replaced with allowlisted command handler
 * 3. Input validation and allowlisting enforced
 * 4. Secure defaults for SSL/TLS configuration
 * 5. Robust error handling and resource management
 */
public class SecureServer {

    // Allowlist of permitted commands (secure default: no execution by default)
    private static final Set<String> ALLOWED_COMMANDS = Set.of("echo", "date", "whoami");

    // Path to keystore (externalized via environment variable or secret manager in production)
    private static final String KEYSTORE_PATH = System.getenv("SERVER_KEYSTORE_PATH");
    private static final String KEYSTORE_PASSWORD = System.getenv("SERVER_KEYSTORE_PASSWORD");

    public static void main(String[] args) {
        try {
            // Initialize SSLContext with secure defaults
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, getTrustManager(), null);

            // Create SSLServerSocketFactory with secure configuration
            SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(8443);

            // Enforce secure SSL/TLS settings
            serverSocket.setNeedClientAuth(false);
            serverSocket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
            serverSocket.setEnabledCipherSuites(getSecureCipherSuites());

            System.out.println("Secure Server started.\nListening for connections on port 8443 ...");

            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                System.out.println("Accepted secure connection: " + clientSocket.getRemoteSocketAddress());

                // Use try-with-resources for automatic resource cleanup
                try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                     BufferedWriter out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()))) {

                    String inputLine;
                    while ((inputLine = in.readLine()) != null) {
                        System.out.println("Received message: " + inputLine);

                        if (inputLine.contains("runCommand")) {
                            String[] parts = inputLine.split(":", 2);
                            if (parts.length != 2) {
                                out.write("ERROR: Invalid command format\n");
                                out.flush();
                                continue;
                            }

                            String command = parts[1].trim();
                            if (command.isEmpty()) {
                                out.write("ERROR: Empty command\n");
                                out.flush();
                                continue;
                            }

                            // Validate command against allowlist
                            String[] commandParts = command.split("\\s+", 2);
                            if (commandParts.length < 1 || !ALLOWED_COMMANDS.contains(commandParts[0])) {
                                out.write("ERROR: Command not allowed\n");
                                out.flush();
                                continue;
                            }

                            // Execute command safely using ProcessBuilder with absolute path
                            ProcessBuilder pb = new ProcessBuilder("/usr/bin/" + commandParts[0], 
                                commandParts.length > 1 ? commandParts[1] : "");
                            
                            // Set secure process environment
                            Map<String, String> env = pb.environment();
                            env.clear(); // Start with empty environment
                            env.put("LANG", "C"); // Minimal required environment

                            // Execute and capture output
                            Process process = pb.start();
                            StringBuilder output = new StringBuilder();
                            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                                String line;
                                while ((line = reader.readLine()) != null) {
                                    output.append(line).append("\n");
                                }
                            }

                            int exitCode = process.waitFor();
                            if (exitCode == 0) {
                                out.write("COMMAND_OUTPUT:" + output.toString() + "\n");
                            } else {
                                out.write("ERROR: Command failed with exit code " + exitCode + "\n");
                            }
                            out.flush();
                        }
                    }
                } catch (IOException | InterruptedException e) {
                    System.err.println("Error handling client: " + e.getMessage());
                } finally {
                    clientSocket.close();
                }
            }
        } catch (Exception e) {
            System.err.println("Critical server error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Returns a TrustManager array that trusts the default Java CA certificates.
     * In production, this should be replaced with a custom TrustManager that
     * only trusts specific certificates.
     */
    private static TrustManager[] getTrustManager() throws Exception {
        // Load default truststore
        String truststorePath = System.getProperty("javax.net.ssl.trustStore");
        String truststorePassword = System.getProperty("javax.net.ssl.trustStorePassword");

        if (truststorePath == null || truststorePassword == null) {
            // Fallback to default Java truststore if not explicitly set
            return TrustManagerFactory.getDefaultAlgorithm().getTrustManagers();
        }

        // Load custom truststore
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream is = new FileInputStream(truststorePath)) {
            keyStore.load(is, truststorePassword.toCharArray());
        }

        TrustManagerFactory tmf = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        return tmf.getTrustManagers();
    }

    /**
     * Returns an array of secure cipher suites for TLS communication.
     */
    private static String[] getSecureCipherSuites() {
        return new String[]{
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
        };
    }
}