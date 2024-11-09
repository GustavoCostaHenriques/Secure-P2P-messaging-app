package com.p2pmessagingapp;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.FileOutputStream;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;

import javax.security.auth.x500.X500Principal;

import java.util.ArrayList;
import java.util.List;
import java.util.Date;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.apache.tomcat.util.http.fileupload.ByteArrayOutputStream;

/**
 * The Server class represents a central server in the P2P messaging
 * application.
 * It handles secure connections from peers, manages a list of connected users,
 * and
 * facilitates secure messaging between peers.
 *
 * The server performs the following main tasks:
 * 1. Initializes a central KeyStore and exports its certificate.
 * 2. Creates a TrustStore to manage trusted peer certificates.
 * 3. Starts an SSL server socket to listen for incoming peer connections.
 * 4. Accepts connections and processes messages securely between peers.
 */
public class Server {

    private static InputStream inputStream; // Input stream to read data from the socket
    private final static int port = 2222; // Port on which the server listens for peer connections
    private static SSLServerSocket serverSocket; // SSLServerSocket to accept secure connections
    private static List<User> userList = new ArrayList<>(); // List to store connected users
    private static User serverUser = new User("SERVER", "localhost", 2222, null, null, null); // Represents the central
                                                                                              // server
    private static User userNull = new User("NULL", "NULL", 0000, null, null, null); // Placeholder user if peer not
                                                                                     // found

    // Define paths for keystore, truststore, and certificate files, and the
    // password
    private static String keyStoreFile = "central_keystore.jks";
    private static String trustStoreFile = "central_truststore.jks";
    private static String password = "centralPassword";
    private static String serverCertFile = "server_certificate.crt";

    /**
     * The entry point of the central server application. It initializes security
     * credentials,
     * sets up the server socket, and starts accepting peer connections for secure
     * communication.
     *
     * The main function performs the following steps:
     * 1. Initializes the KeyStore and exports the central server's certificate.
     * 2. Sets up the TrustStore for trusted peers.
     * 3. Creates an SSL server socket to handle secure peer connections.
     * 4. Enters an infinite loop to continuously accept and process peer
     * connections.
     *
     * @param args Command-line arguments (not used in this application).
     */
    public static void main(String[] args) {
        // Add a shutdown hook to delete server files on exit
        addShutdownHook();

        try {
            // Initialize the KeyStore for the central server
            createCentralServerKeyStore(keyStoreFile, password);

            // Export the server's certificate to a .crt file
            exportServerCertificate(keyStoreFile, password, "centralServer", serverCertFile);

            // Create the TrustStore for trusted peers
            X509Certificate[] peerCertificates = null;
            createCentralServerTrustStore(trustStoreFile, password, peerCertificates);

            // Initialize the SSL server socket for secure peer communication
            createSSLServerSocket(port, keyStoreFile, trustStoreFile, password);

            // Accept and process incoming peer connections
            acceptConnections();

            // Keep the server running indefinitely
            keepProgramRunning();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Continuously accepts incoming connections from peers, initiating secure
     * communication and processing messages from connected peers.
     */
    private static void acceptConnections() {
        while (true) {
            try {
                // Accept incoming SSL connections from peers
                SSLSocket sslSocket = (SSLSocket) serverSocket.accept();
                // Process incoming messages from connected peers
                processMessage(sslSocket);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // -------------------------------------------------------SSLSOCKET-SETUP-------------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Adds a peer's certificate to the TrustStore to establish secure
     * communication.
     * 
     * @param trustStoreFile     The path to the TrustStore file.
     * @param trustStorePassword The password to unlock the TrustStore.
     * @param peerCert           The certificate of the peer being added to the
     *                           TrustStore.
     * @param alias              A unique alias for storing the peer's certificate
     *                           in the TrustStore.
     * @throws Exception If an error occurs while accessing or updating the
     *                   TrustStore.
     */
    private static void addPeerCertificateToTrustStore(String trustStoreFile, String trustStorePassword,
            X509Certificate peerCert, String alias) throws Exception {
        // Load the existing TrustStore
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(trustStoreFile)) {
            trustStore.load(fis, trustStorePassword.toCharArray());
        }

        // Add the peer's certificate to the TrustStore with the specified alias
        trustStore.setCertificateEntry(alias, peerCert);

        // Save the updated TrustStore to persist the changes
        try (FileOutputStream fos = new FileOutputStream(trustStoreFile)) {
            trustStore.store(fos, trustStorePassword.toCharArray());
        }
    }

    /**
     * Creates a KeyStore for the central server with a self-signed certificate.
     * 
     * @param keyStoreFile The path to the KeyStore file.
     * @param password     The password to protect the KeyStore.
     * @throws Exception If an error occurs during KeyStore or certificate
     *                   generation.
     */
    private static void createCentralServerKeyStore(String keyStoreFile, String password) throws Exception {
        // Generate a KeyPair (private and public keys) for the central server
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // Generate a self-signed certificate for the central server using the KeyPair
        X509Certificate cert = generateSelfSignedCertificate(keyPair, "CN=CentralServer");

        // Create a new KeyStore and add the private key and certificate to it
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, password.toCharArray());
        keyStore.setKeyEntry("centralServer", keyPair.getPrivate(), password.toCharArray(),
                new java.security.cert.Certificate[] { cert });

        // Save the KeyStore to a file
        try (FileOutputStream fos = new FileOutputStream(keyStoreFile)) {
            keyStore.store(fos, password.toCharArray());
        }
    }

    /**
     * Generates a self-signed X509 certificate for the specified KeyPair.
     * 
     * @param keyPair The KeyPair containing the public and private keys for the
     *                certificate.
     * @param dn      The distinguished name (DN) for the certificate.
     * @return A self-signed X509 certificate.
     * @throws Exception If an error occurs during certificate generation.
     */
    private static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String dn) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365 * 24 * 60 * 60 * 1000L); // 1 year validity period

        X500Principal dnName = new X500Principal(dn);
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, new java.math.BigInteger(Long.toString(now)), startDate, endDate, dnName, keyPair.getPublic());

        // Convert the certificate builder into an X509Certificate instance
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
    }

    /**
     * Creates a TrustStore for the central server, optionally initializing it with
     * peer certificates.
     * 
     * @param trustStoreFile   The path to the TrustStore file.
     * @param password         The password to protect the TrustStore.
     * @param peerCertificates An array of certificates to be added to the
     *                         TrustStore.
     * @throws Exception If an error occurs during TrustStore creation or saving.
     */
    private static void createCentralServerTrustStore(String trustStoreFile, String password,
            X509Certificate[] peerCertificates) throws Exception {
        // Create a new, empty TrustStore
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, password.toCharArray());

        // Save the TrustStore to a file to persist it for future use
        try (FileOutputStream fos = new FileOutputStream(trustStoreFile)) {
            trustStore.store(fos, password.toCharArray());
        }
    }

    /**
     * Exports a certificate from the specified KeyStore to a .crt file.
     * 
     * @param keyStoreFile     The path to the KeyStore file containing the
     *                         certificate.
     * @param keyStorePassword The password to access the KeyStore.
     * @param alias            The alias under which the certificate is stored in
     *                         the KeyStore.
     * @param outputCertFile   The output file path for the exported certificate.
     * @throws Exception If an error occurs while accessing the KeyStore or writing
     *                   the certificate.
     */
    private static void exportServerCertificate(String keyStoreFile, String keyStorePassword, String alias,
            String outputCertFile) throws Exception {
        // Load the KeyStore containing the certificate to export
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keyStoreFile)) {
            keyStore.load(fis, keyStorePassword.toCharArray());
        }

        // Retrieve the certificate using the specified alias
        Certificate cert = keyStore.getCertificate(alias);

        // Write the certificate to a .crt file in binary encoding
        try (FileOutputStream fos = new FileOutputStream(outputCertFile)) {
            fos.write(cert.getEncoded());
        }
    }

    /**
     * Creates an SSLServerSocket configured with the specified KeyStore and
     * TrustStore for secure communication.
     * 
     * @param port           The port number for the server socket.
     * @param keyStoreFile   The path to the KeyStore file containing the server's
     *                       private key and certificate.
     * @param trustStoreFile The path to the TrustStore file containing trusted peer
     *                       certificates.
     * @param password       The password for both KeyStore and TrustStore.
     */
    private static void createSSLServerSocket(int port, String keyStoreFile, String trustStoreFile, String password) {
        try {
            // Initialize SSL context with TLS v1.2 protocol
            SSLContext context = SSLContext.getInstance("TLSv1.2");

            // Load the KeyStore with the server's private key and certificate
            KeyManagerFactory keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (InputStream keyStream = new FileInputStream(keyStoreFile)) {
                keyStore.load(keyStream, password.toCharArray());
            }
            keyManager.init(keyStore, password.toCharArray());

            // Load the TrustStore containing certificates of trusted peers
            TrustManagerFactory trustManager = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream trustStream = new FileInputStream(trustStoreFile)) {
                trustStore.load(trustStream, password.toCharArray());
            }
            trustManager.init(trustStore);

            // Initialize SSL context with the loaded KeyManager and TrustManager
            context.init(keyManager.getKeyManagers(), trustManager.getTrustManagers(), null);

            // Create an SSLServerSocket using the configured SSL context
            SSLServerSocketFactory factory = context.getServerSocketFactory();
            serverSocket = (SSLServerSocket) factory.createServerSocket(port);

        } catch (Exception e) {
            e.printStackTrace(); // Log any exceptions that occur during server socket creation
        }
    }

    /**
     * Creates an SSLSocket for secure communication, using specified KeyStore and
     * TrustStore files.
     * 
     * @param ip             The IP address of the server or peer to connect to.
     * @param port           The port number of the server or peer to connect to.
     * @param keyStoreFile   The path to the KeyStore file containing the peer's
     *                       private key and certificate.
     * @param trustStoreFile The path to the TrustStore file containing trusted
     *                       certificates.
     * @param password       The password for both the KeyStore and TrustStore.
     * @return The configured SSLSocket instance.
     */
    private static SSLSocket createSSLSocket(String ip, int port, String keyStoreFile, String trustStoreFile,
            String password) {
        SSLSocket socket = null;
        try {
            // Initialize SSL context with TLS v1.2 protocol
            SSLContext context = SSLContext.getInstance("TLSv1.2");

            // Load the KeyStore with the peer's private key and certificate
            KeyManagerFactory keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (InputStream keyStream = new FileInputStream(keyStoreFile)) {
                keyStore.load(keyStream, password.toCharArray());
            }
            keyManager.init(keyStore, password.toCharArray());

            // Load the TrustStore containing trusted peer certificates
            TrustManagerFactory trustManager = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream trustStream = new FileInputStream(trustStoreFile)) {
                trustStore.load(trustStream, password.toCharArray());
            }
            trustManager.init(trustStore);

            // Initialize SSL context with the loaded KeyManager and TrustManager
            context.init(keyManager.getKeyManagers(), trustManager.getTrustManagers(), null);

            // Create an SSLSocket using the configured SSL context
            SSLSocketFactory factory = context.getSocketFactory();
            socket = (SSLSocket) factory.createSocket(ip, port);

        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException
                | CertificateException | KeyManagementException e) {
            e.printStackTrace(); // Log any exceptions that occur during socket creation
        }
        return socket; // Return the configured SSLSocket instance
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ------------------------------------------------------MESSAGE-HANDLING-------------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Processes incoming messages from the specified SSLSocket, determining actions
     * based on message type.
     * 
     * @param sslSocket The SSLSocket from which to read the incoming message.
     */
    private static void processMessage(SSLSocket sslSocket) {
        Message message = null; // Initialize a Message object for possible sending
        Boolean needsTosend = false; // Flag to check if a response message needs to be sent

        try {
            inputStream = sslSocket.getInputStream(); // Get the input stream from the SSL socket
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream); // Create ObjectInputStream for
                                                                                      // reading objects
            User user = (User) objectInputStream.readObject(); // Deserialize the User object from input

            X509Certificate peerCertificate = user.getCertificate(); // Retrieve the certificate from the User object

            // Check if it's a connection request with user IP and port specified but no
            // receiver ID
            if (user.getIp() != null && user.getPort() != 0000 && user.getReceiverId() == null) {
                userList.add(user); // Add user to the connected users list
                String peerAlias = "peer-" + user.getId();

                // Attempt to add the peer's certificate to the TrustStore
                try {
                    addPeerCertificateToTrustStore(trustStoreFile, password, peerCertificate, peerAlias);
                } catch (Exception e) {
                    e.printStackTrace(); // Log any issues during the TrustStore update
                }
            }
            // Check if it's a request to locate another user by ID (receiver ID specified,
            // no IP or port)
            else if (user.getIp() == null && user.getPort() == 0000 && user.getReceiverId() != null) {
                needsTosend = true; // Flag as needing to send a response message
                User foundUser = findUserById(user.getReceiverId()); // Look up the requested user in userList
                message = new Message(serverUser, foundUser, null, null); // Prepare a response message to send to the
                                                                          // user
            }
            // If IP, port, and receiver ID are all null, treat it as a user disconnect
            // request
            else if (user.getIp() == null && user.getPort() == 0000 && user.getReceiverId() == null)
                removeUserById(user.getId()); // Remove the user from the list

            // Find the user information of the sender for creating the response connection
            User userToSend = findUserById(user.getId());

            // If a response message needs to be sent, establish a connection to the
            // requester
            if (needsTosend) {
                SSLSocket sslClientSocket = createSSLSocket(userToSend.getIp(), userToSend.getPort(), keyStoreFile,
                        trustStoreFile, password);

                sendMessageToPeer(sslClientSocket, message); // Send the response message to the peer
            }

        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace(); // Log any exceptions during message processing
        }
    }

    /**
     * Sends a serialized Message to a specified peer using an SSLSocket.
     * 
     * @param sslSocket The SSLSocket through which the message will be sent.
     * @param message   The Message object to send.
     */
    private static void sendMessageToPeer(SSLSocket sslSocket, Message message) {
        try (OutputStream outputStream = sslSocket.getOutputStream()) {
            byte[] serializedUser = serializeMessage(message); // Convert the Message to a byte array
            outputStream.write(serializedUser); // Send the serialized message through the output stream
            outputStream.flush(); // Flush the stream to ensure immediate send
            sslSocket.close(); // Close the socket after sending
        } catch (IOException e) {
            e.printStackTrace(); // Log any issues during message sending
        }
    }

    /**
     * Serializes a Message object into a byte array for transmission.
     *
     * @param message The Message object to be serialized.
     * @return A byte array representing the serialized Message.
     * @throws IOException If an error occurs during serialization.
     */
    private static byte[] serializeMessage(Message message) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(); // Create a byte array output stream

        // Serialize the Message object into the byte array output stream
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {
            objectOutputStream.writeObject(message); // Serialize the Message object
        }

        return byteArrayOutputStream.toByteArray(); // Return the resulting byte array
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------AUXILIARY-FUNCTIONS------------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    private static User findUserById(String receiverId) {
        for (User u : userList) {
            if (u.getId().equals(receiverId))
                return u;
        }
        return userNull;
    }

    private static void removeUserById(String receiverId) {
        userList.removeIf(u -> u.getId().equals(receiverId));
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------KILLING-SERVER-PROCESS---------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Deletes all the secure files of this user.
     */
    private static void deleteSecureFiles() {
        // Deletion of KeyStore
        File keyStore = new File(keyStoreFile);
        keyStore.delete();

        // Deletion of TrustStore
        File trustStore = new File(trustStoreFile);
        trustStore.delete();

        // Deletion of Certificate
        File serverCertificate = new File(serverCertFile);
        serverCertificate.delete();
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ------------------------------------------------PROGRAM-LIFECYCLE-MANAGEMENT-------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Adds a shutdown hook to the runtime to handle cleanup when the program is
     * terminated.
     */
    private static void addShutdownHook() {
        // Register a new thread to be executed on program shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            deleteSecureFiles();
        }));
    }

    /**
     * Keeps the program running indefinitely until interrupted.
     */
    private static void keepProgramRunning() {
        new Thread(() -> {
            try {
                while (true) {
                    Thread.sleep(1000);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
    }
}