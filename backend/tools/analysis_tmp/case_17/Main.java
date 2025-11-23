import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class SecureServer {

    // TODO: Load keystore/truststore from secure secret manager or environment variables
    private static final String KEYSTORE_PATH = System.getProperty("javax.net.ssl.keyStore");
    private static final String KEYSTORE_PASSWORD = System.getProperty("javax.net.ssl.keyStorePassword");
    private static final String TRUSTSTORE_PATH = System.getProperty("javax.net.ssl.trustStore");
    private static final String TRUSTSTORE_PASSWORD = System.getProperty("javax.net.ssl.trustStorePassword");

    public static void main(String[] args) {
        try {
            // Initialize SSLContext with default TLS protocol (TLSv1.3 preferred)
            SSLContext sslContext = SSLContext.getInstance("TLS");

            // Initialize KeyManagerFactory and TrustManagerFactory
            KeyManagerFactory kmf = KeyManagerFactory
                    .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            TrustManagerFactory tmf = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());

            // Load keystore and truststore
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());
            kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());
            tmf.init(trustStore);

            // Initialize SSLContext
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            // Create SSLServerSocketFactory and bind to port
            SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(8080);

            // Set secure SSL/TLS defaults
            serverSocket.setNeedClientAuth(false); // Set to true if mutual TLS is required
            serverSocket.setEnabledCipherSuites(sslContext.getSupportedSSLParameters().getCipherSuites());

            System.out.println("Secure server started on port 8080");

            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                clientSocket.startHandshake(); // Ensure TLS handshake completes

                // Wrap streams with try-with-resources for automatic closure
                try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                     PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

                    String inputLine;
                    while ((inputLine = in.readLine()) != null) {
                        // Basic input validation to prevent injection attacks
                        if (inputLine == null || inputLine.isEmpty() || inputLine.length() > 1024) {
                            out.println("ERROR: Invalid input");
                            break;
                        }

                        // Echo input back to client
                        out.println(inputLine);
                    }
                } catch (IOException e) {
                    System.err.println("Error handling client: " + e.getMessage());
                } finally {
                    clientSocket.close();
                }
            }
        } catch (Exception e) {
            System.err.println("Critical error in server setup: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}