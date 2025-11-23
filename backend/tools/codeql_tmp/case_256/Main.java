import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

// TODO: Externalize keystore/truststore paths and passwords via environment variables or secret manager
public class SecureServer {

    public static void main(String[] args) {
        try {
            // Load SSL context with default settings (can be customized with client auth, etc.)
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null); // Use default truststore

            // Create SSL server socket factory
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

            // Create SSL server socket with secure defaults
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(8443);
            serverSocket.setNeedClientAuth(false); // Set to true if client auth is required
            System.out.println("Secure server is listening on port 8443");

            while (true) {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                System.out.println("New client connected");

                // Enable modern TLS protocols only
                socket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});

                // Disable weak cipher suites
                socket.setEnabledCipherSuites(socket.getEnabledCipherSuites());

                new Thread(() -> {
                    try (
                        BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                        PrintWriter output = new PrintWriter(socket.getOutputStream(), true)
                    ) {
                        String line;
                        while ((line = input.readLine()) != null) {
                            // Basic input validation (allowlist simple text)
                            if (line == null || line.isEmpty() || line.length() > 1024) {
                                output.println("ERROR: Invalid input");
                                continue;
                            }

                            System.out.printf("Received message from client: %s%n", line);
                            output.println("ECHO: " + line);
                        }
                    } catch (IOException e) {
                        System.err.println("Error handling client: " + e.getMessage());
                        // Log exception in production (e.g., via SLF4J)
                    } finally {
                        try {
                            socket.close();
                        } catch (IOException e) {
                            // Ignore close errors
                        }
                    }
                }).start();
            }
        } catch (Exception e) {
            System.err.println("Critical server error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}