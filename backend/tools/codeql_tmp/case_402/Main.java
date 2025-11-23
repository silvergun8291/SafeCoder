import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class SecureServer {

    // TODO: Externalize keystore/truststore paths and passwords via environment variables or secret manager
    private static final String KEYSTORE_PATH = System.getenv("SERVER_KEYSTORE_PATH");
    private static final String KEYSTORE_PASSWORD = System.getenv("SERVER_KEYSTORE_PASSWORD");
    private static final String TRUSTSTORE_PATH = System.getenv("SERVER_TRUSTSTORE_PATH");
    private static final String TRUSTSTORE_PASSWORD = System.getenv("SERVER_TRUSTSTORE_PASSWORD");

    public static void main(String[] args) {
        try {
            // Initialize SSLContext with mutual TLS (mTLS) support
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");

            // Initialize KeyManagers (server certificate)
            KeyManagerFactory kmf = KeyManagerFactory
                .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

            // Initialize TrustManagers (client certificate validation)
            TrustManagerFactory tmf = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyStore ts = KeyStore.getInstance("JKS");
            ts.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());
            tmf.init(ts);

            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            // Create SSLServerSocketFactory with secure defaults
            SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(8443);

            // Enforce TLS 1.2+ and disable weak ciphers
            serverSocket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
            serverSocket.setEnabledCipherSuites(serverSocket.getEnabledCipherSuites());

            System.out.println("Secure server is listening on port 8443");

            while (true) {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                System.out.println("New client connected");

                // Start a new thread to handle the client
                new Thread(() -> handleClient(socket)).start();
            }
        } catch (Exception e) {
            System.err.println("Critical error in server setup: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void handleClient(SSLSocket socket) {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true)
        ) {
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                // Basic input validation (allow only alphanumeric + spaces)
                if (inputLine == null || inputLine.matches(".*[^a-zA-Z0-9 ].*")) {
                    out.println("ERROR: Invalid input format");
                    continue;
                }

                System.out.println("Received: " + inputLine);
                out.println("ECHO: " + Base64.getEncoder().encodeToString(inputLine.getBytes()));
            }
        } catch (IOException e) {
            System.err.println("Error handling client: " + e.getMessage());
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                System.err.println("Error closing socket: " + e.getMessage());
            }
        }
    }
}