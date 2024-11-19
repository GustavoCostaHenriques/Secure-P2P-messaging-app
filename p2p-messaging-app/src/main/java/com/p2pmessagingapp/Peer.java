package com.p2pmessagingapp;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ObjectOutputStream;
import java.io.FileOutputStream;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.math.BigInteger;

import java.nio.charset.StandardCharsets;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.*;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;

import com.codahale.shamir.Scheme;

import io.github.cdimascio.dotenv.Dotenv;

import org.apache.tomcat.util.http.fileupload.ByteArrayOutputStream;

/**
 * The Peer class represents a peer in the P2P messaging application.
 * It handles user interaction, manages the peer server, and facilitates
 * communication between users.
 */
public class Peer {

    private SSLSocket sslSocket; // SSL socket for secure communication
    private SSLSocket sslServerSocket; // SSL server socket for communication with server
    private String[] values = new String[3]; // Array to hold user input values (ID, port and IP)
    private List<String> interests = new ArrayList<>(); // List of interests
    private final List<Message> messageHistory = new CopyOnWriteArrayList<>(); // List to store all messages for this
                                                                               // peer
    private PeerServer serverThread; // Thread for the peer server
    private boolean verificationStatus = true; // Boolean that checks the values of this peer
    private boolean repeatedId = false; // Boolean that checks the values of this peer
    private boolean repeatedPort = false; // Boolean that checks the values of this peer
    private User user; // User that will be created for this peer
    private final String serverIp = "localhost"; // IP of the server that has information about other peers
    private final int serverPort = 2222; // Port of the server that has information about other peers
    private boolean firstMessageSent = true; // Bool that checks if it's the first message that this peer is sending
    private SecretKey aesKey; // Secret Key of the peer to encrypt messages to store in the cloud
    private volatile User userFound; // Using 'volatile' on serverResponse to ensure visibility across threads and
                                     // prevent infinite loop due to caching issues
    private Map<String, Key> groupKeys = new HashMap<>();
    // Variables that will store the paths for the keystore, truststore and server
    // certificate
    private String keyStoreFile;
    private String trustStoreFile;
    private String serverCertFile;
    private String password; // Password of this user, to manage the security of keystore and truststore
    private X509Certificate cert; // Certificate of thi user

    /**
     * Starts the peer, setting up necessary SSL configuration and launching the
     * server.
     *
     * @param args Arguments received from the submissionForm in the PeerController.
     * @throws Exception If an error occurs during initialization or communication.
     */
    public void startPeer(String[] args, List<String> interests) throws Exception {
        // Adds a shutdown hook to delete client and port files/directories upon exiting
        addShutdownHook(this); // Triggered by pressing 'Control + C'

        // Store user values (ID, IP, port) in the values array
        for (int i = 0; i < 3; i++) {
            this.values[i] = args[i];
        }
        this.interests = interests;

        // Define paths and passwords for KeyStore and TrustStore files
        keyStoreFile = "peer_keystore_" + this.values[0] + ".jks";
        trustStoreFile = "peer_truststore_" + this.values[0] + ".jks";
        password = "p2pmessagingapp_" + this.values[0];
        serverCertFile = "server_certificate.crt";

        // Check if a KeyStore already exists for this peer to avoid duplicate entries
        File keyStore = new File(keyStoreFile);

        if (keyStore.exists()) {
            setVerificationStatus(this, false); // Mark verification as failed
            setRepeatedId(this, true); // Indicate duplicate ID found
        }

        // Generate new KeyStore and TrustStore for the peer
        generatePeerKeyStore("peerAlias", password, keyStoreFile);
        generateTrustStore(trustStoreFile, password);

        // Add server certificate to peer's TrustStore for trusted communication
        addServerCertToPeerTrustStore(trustStoreFile, password, serverCertFile);

        // Create a User object with peer's details (for later communication)
        user = new User(this.values[0], this.values[2], Integer.parseInt(this.values[1]), null, cert, interests);

        // Add peer's own certificate to TrustStore for secure, mutual authentication
        addPeerCertificateToTrustStore(user, trustStoreFile, password);

        // Initialize the PeerServer instance on specified port
        serverThread = new PeerServer(Integer.parseInt(this.values[1]), keyStoreFile, trustStoreFile, password, this);

        // Check if the server was successfully created; if not, mark port as repeated
        if (!serverThread.getServerCreated()) {
            setRepeatedPort(this, true);
            setVerificationStatus(this, false); // Fail verification due to port issue
        }

        // Verify the IP format; fail verification if invalid IP
        if (!isValidIP(this.values[2]))
            setVerificationStatus(this, false);

        // If verification passed, start server and SSL communication
        if (this.verificationStatus) {
            serverThread.start(); // Start the PeerServer thread

            // Create SSL sockets to communicate with peers and the server
            sslSocket = createSSLSocket(this.values[2], Integer.parseInt(this.values[1]), keyStoreFile, trustStoreFile,
                    password);
            sslServerSocket = createSSLSocket(serverIp, serverPort, keyStoreFile, trustStoreFile, password);

            // Send initial user data to the server
            sendMessageToServer(user);

            // Keep the program running indefinitely
            keepProgramRunning();
        } else {
            // If verification failed, close the server socket if created
            if (serverThread.getServerCreated())
                serverThread.closeServerSocket();
        }
    }

    /**
     * Constructs a Peer instance with specified attributes, initializing SSL
     * configuration.
     *
     * @param id     The ID of the user.
     * @param ip     The IP address of the user.
     * @param port   The port number used for communication.
     * @param sender The User object representing the sender creating this peer.
     * @throws Exception If an error occurs during initialization.
     */
    public Peer(String id, String ip, int port, List<String> interests, User sender) throws Exception {
        // Initialize the peer's basic details
        this.values[0] = id;
        this.values[1] = String.valueOf(port);
        this.values[2] = ip;

        // Define KeyStore, TrustStore files, and password based on peer ID
        keyStoreFile = "peer_keystore_" + this.values[0] + ".jks";
        trustStoreFile = "peer_truststore_" + this.values[0] + ".jks";
        password = "p2pmessagingapp_" + this.values[0];
        serverCertFile = "server_certificate.crt";

        // Add the sender's certificate to the TrustStore for secure communication
        addPeerCertificateToTrustStore(sender, trustStoreFile, password);

        // Create a User instance for this peer with the given ID, IP, and port
        user = new User(this.values[0], this.values[2], Integer.parseInt(this.values[1]), null, cert, interests);

        // Create an SSL socket for secure communication with the given IP and port
        this.sslSocket = createSSLSocket(ip, port, keyStoreFile, trustStoreFile, password);

        // Initialize the PeerServer on the specified port for incoming connections
        // (this serves to update the socket with the new certificates on the
        // peerServer side)
        serverThread = new PeerServer(Integer.parseInt(this.values[1]), keyStoreFile, trustStoreFile, password, this);
    }

    /**
     * Constructs a Peer instances.
     * 
     */
    public Peer() {
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // -----------------------------------------------COMMUNICATION-MANAGEMENT------------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Asks the server for the user with the otherPeerID and returns this user.
     * 
     * @param otherPeerID Id of the peer we want to communicate with.
     * @return The User that the server sends (this user can have the id equal to
     *         "NULL" meaning that the user was not found).
     */
    public User checkscommunication(String otherPeerID) throws Exception {

        User receiverUser = new User(values[0], null, 0000, otherPeerID, null, null);
        sendMessageToServer(receiverUser);

        // Wait for the server response
        userFound = serverThread.getUserSearched();
        while (userFound == null) {
            userFound = serverThread.getUserSearched();
        }

        serverThread.setUserSearched(null);

        // If the user was found, add their certificate to this peer's TrustStore
        if (!userFound.getId().equals("NULL") && userFound.getCertificate() != null)
            // Add the certificate of the found peer to the TrustStore for secure
            // communication
            addPeerCertificateToTrustStore(userFound, trustStoreFile, password);

        return userFound;
    }

    /**
     * Handles the communication between users.
     *
     * @param receiver The user to communicate with.
     * @param content  The content of the message that is going to be sent.
     */
    public void communicate(User receiver, String content) {

        // Create a message and send it to the receiver
        Message message = new Message(user, receiver, content);

        try {

            this.serverThread.sendMessage(message); // Send the message through the server thread
            // Add to the message history
            addMessageToHistory(message);

            LocalDateTime timeStap = LocalDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("ddMMyy-HH:mm");
            String formattedTimestamp = timeStap.format(formatter);
            String objectKey = "CHATS/" + user.getId() + "/" + receiver.getId() + "_" + formattedTimestamp;

            this.sendMessageToCloud(objectKey, content);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Sends a serialized message through the secure socket.
     *
     * @param serializedMessage The message to be sent in byte array format.
     */
    public void sendMessage(byte[] serializedMessage) {
        try (OutputStream outputStream = sslSocket.getOutputStream()) {
            outputStream.write(serializedMessage);
            outputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Sends a serialized user through the secure server socket.
     * 
     * @param user The user to be serialized and sent.
     */
    private void sendMessageToServer(User user) {
        if (sslServerSocket == null || sslServerSocket.isClosed())
            sslServerSocket = createSSLSocket(serverIp, serverPort, keyStoreFile, trustStoreFile, password);

        try (OutputStream outputStream = sslServerSocket.getOutputStream();) {
            byte[] serializedUser = serializeUser(user);
            // Send a message based on user data
            outputStream.write(serializedUser);
            outputStream.flush(); // Ensure the message is sent immediately

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // -------------------------------------------------------SSLSOCKET-SETUP-------------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Adds the certificate of a peer to this peer's TrustStore to enable secure
     * communication.
     * 
     * @param peerUser       The User object of the peer whose certificate needs to
     *                       be added.
     * @param trustStoreFile The path to the TrustStore file where the certificate
     *                       will be stored.
     * @param password       The password for the TrustStore file.
     * @throws Exception If any error occurs while accessing or modifying the
     *                   TrustStore.
     */
    public void addPeerCertificateToTrustStore(User peerUser, String trustStoreFile, String password)
            throws Exception {
        // Load the peer's TrustStore
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(trustStoreFile)) {
            trustStore.load(fis, password.toCharArray());
        }

        // Define a unique alias for the peer's certificate
        String alias = "peer-" + peerUser.getId();

        // Check if the certificate already exists in the TrustStore
        if (trustStore.containsAlias(alias))
            return; // Skip adding if the certificate is already present

        // Retrieve the certificate of the peer from the User object
        X509Certificate peerCert = peerUser.getCertificate();

        // Add the peer's certificate to the TrustStore
        trustStore.setCertificateEntry(alias, peerCert);

        // Save the updated TrustStore to persist the changes
        try (FileOutputStream fos = new FileOutputStream(trustStoreFile)) {
            trustStore.store(fos, password.toCharArray());
        }
    }

    /**
     * Adds the server's certificate to the peer's TrustStore for secure
     * communication.
     *
     * @param trustStoreFile The file path to the peer's TrustStore.
     * @param password       The password for the TrustStore.
     * @param serverCertFile The file path to the server's certificate (.crt file).
     * @throws Exception If an error occurs while accessing or modifying the
     *                   TrustStore.
     */
    public void addServerCertToPeerTrustStore(String trustStoreFile, String password, String serverCertFile)
            throws Exception {
        // Load the peer's TrustStore
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(trustStoreFile)) {
            trustStore.load(fis, password.toCharArray());
        }

        // Load the server's certificate from the exported .crt file
        try (FileInputStream certStream = new FileInputStream(serverCertFile)) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate serverCert = (X509Certificate) certFactory.generateCertificate(certStream);

            // Add the server's certificate to the TrustStore
            trustStore.setCertificateEntry("centralServer", serverCert);
        }

        // Save the updated TrustStore
        try (FileOutputStream fos = new FileOutputStream(trustStoreFile)) {
            trustStore.store(fos, password.toCharArray());
        }
    }

    /**
     * Generates a new KeyStore file for the peer, containing the peer's private key
     * and self-signed certificate.
     *
     * @param alias        The alias for the key entry in the KeyStore.
     * @param password     The password for the KeyStore.
     * @param keyStoreFile The file path to save the KeyStore.
     * @throws Exception If an error occurs during KeyStore creation or while saving
     *                   the KeyStore.
     */
    private void generatePeerKeyStore(String alias, String password, String keyStoreFile) throws Exception {
        // Generate a KeyPair (public and private keys)
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // Generate a self-signed certificate for the peer
        cert = generateSelfSignedCertificate(keyPair, alias);

        // Create a new KeyStore and add the private key and certificate
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, password.toCharArray());
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(),
                new java.security.cert.Certificate[] { cert });

        // Save the KeyStore to a file
        try (FileOutputStream fos = new FileOutputStream(keyStoreFile)) {
            keyStore.store(fos, password.toCharArray());
        }
    }

    /**
     * Generates a self-signed X.509 certificate for the peer.
     *
     * @param keyPair The KeyPair containing the peer's public and private keys.
     * @param alias   The alias used in the certificate's distinguished name (DN).
     * @return A self-signed X509Certificate for the peer.
     * @throws Exception If an error occurs during the certificate creation or
     *                   signing process.
     */
    private X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String alias) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Principal dnName = new X500Principal("CN=" + alias);
        Date endDate = new Date(now + 365 * 24 * 60 * 60 * 1000L); // 1-year validity

        // Create a signature using SHA256 with RSA
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, BigInteger.valueOf(now), startDate, endDate, dnName, keyPair.getPublic());

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
    }

    /**
     * Generates a new, empty TrustStore file for the peer.
     *
     * @param trustStoreFile The file path to save the TrustStore.
     * @param password       The password for the TrustStore.
     * @throws Exception If an error occurs during TrustStore creation or while
     *                   saving the TrustStore.
     */
    private void generateTrustStore(String trustStoreFile, String password) throws Exception {
        // Create a new TrustStore
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, password.toCharArray());

        // Save the TrustStore to a file
        try (FileOutputStream fos = new FileOutputStream(trustStoreFile)) {
            trustStore.store(fos, password.toCharArray());
        }
    }

    /**
     * Creates an SSL socket for secure communication with the specified ip address
     * and port.
     *
     * @param ip   The ip address to connect to.
     * @param port The port number to connect to.
     * @return socket The socket that the peer wants to create.
     */

    private static SSLSocket createSSLSocket(String ip, int port, String keyStoreFile, String trustStoreFile,
            String password) {
        SSLSocket socket = null;
        try {
            // Initialize SSL context with TLS v1.2 protocol
            SSLContext context = SSLContext.getInstance("TLSv1.2");

            // Load KeyStore containing the peer's private key and certificate
            KeyManagerFactory keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (InputStream keyStream = new FileInputStream(keyStoreFile)) {
                keyStore.load(keyStream, password.toCharArray());
            }
            keyManager.init(keyStore, password.toCharArray());

            TrustManagerFactory trustManager = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream trustStream = new FileInputStream(trustStoreFile)) {
                trustStore.load(trustStream, password.toCharArray());
            }
            trustManager.init(trustStore);

            // Initialize SSL context with KeyManager and TrustManager
            context.init(keyManager.getKeyManagers(), trustManager.getTrustManagers(), null);

            // Create the SSL socket using the configured SSL context
            SSLSocketFactory factory = context.getSocketFactory();
            socket = (SSLSocket) factory.createSocket(ip, port);

        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException
                | CertificateException | KeyManagementException e) {
            e.printStackTrace();
        }
        return socket;
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ------------------------------------------------CLOUD-STORAGE-UNITS-MANAGEMENT-----------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    private void sendMessageToCloud(String objectKey, String content) {

        try {

            if (firstMessageSent) {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256); // Usa 128, 192, ou 256 bits, dependendo do suporte
                aesKey = keyGen.generateKey();
            }

            // Encrypt the message using AES
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedContent = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));

            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(encryptedContent.length);

            // Upload the encrypted content to each cloud provider (AWS, Firebase, Azure)
            uploadToCloud(encryptedContent, objectKey, metadata);

            if (firstMessageSent) {
                // Store key shares across different storage providers
                // Split the AES key using Shamir's Secret Sharing
                Scheme scheme = new Scheme(new SecureRandom(), 12, 8); // 12 parts, minimum of 8 to reconstruct
                Map<Integer, byte[]> keyShares = scheme.split(aesKey.getEncoded());

                storeKeyShares(keyShares, metadata);
            }
            firstMessageSent = false;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void uploadToCloud(byte[] encryptedContent, String objectKey,
            ObjectMetadata metadata) {

        // Define AWS buckets
        String[] awsBuckets = {
                Dotenv.load().get("S3_BUCKET_NAME_1"),
                Dotenv.load().get("S3_BUCKET_NAME_2"),
                Dotenv.load().get("S3_BUCKET_NAME_3"),
                Dotenv.load().get("S3_BUCKET_NAME_4")
        };

        // Upload to AWS
        for (String awsBucket : awsBuckets) {
            S3Config.s3Client.putObject(
                    new PutObjectRequest(awsBucket, objectKey, new ByteArrayInputStream(encryptedContent), metadata));
        }

        // Upload to Firebase
        FirebaseService firebaseService = new FirebaseService();
        String[] fbContainers = { "bucket_chats1", "bucket_chats2", "bucket_chats3", "bucket_chats4" };
        for (String fbContainer : fbContainers) {
            firebaseService.saveMessage(fbContainer, objectKey, Base64.getEncoder().encodeToString(encryptedContent));
        }

        // Upload to Azure
        AzureBlobService azureBlobService = new AzureBlobService();
        String[] azureContainers = { "bucket-chats1", "bucket-chats2", "bucket-chats3", "bucket-chats4" };
        for (String container : azureContainers) {
            azureBlobService.uploadMessage(container, objectKey, new ByteArrayInputStream(encryptedContent));
        }
    }

    private void storeKeyShares(Map<Integer, byte[]> keyShares, ObjectMetadata metadata) {
        int count = 0;

        // Store key shares in AWS
        for (Map.Entry<Integer, byte[]> share : keyShares.entrySet()) {
            if (count < 4) {
                String awsBucket = Dotenv.load().get("S3_BUCKET_NAME_" + (count + 1));
                S3Config.s3Client.putObject(new PutObjectRequest(awsBucket, "KEYS/" + this.values[0],
                        new ByteArrayInputStream(share.getValue()), metadata));
            }
            count++;
            if (count >= 12)
                break;
        }

        // Define the buckets for Firebase
        String[] fbBuckets = { "bucket_chats1", "bucket_chats2", "bucket_chats3", "bucket_chats4" };

        // Initialize the FirebaseService
        FirebaseService firebaseService = new FirebaseService();

        // Create a new Map to hold only the selected keyShares (5th to 8th part)
        Map<Integer, byte[]> firebaseKeyShares = new HashMap<>();

        count = 0;
        for (Map.Entry<Integer, byte[]> share : keyShares.entrySet()) {
            if (count >= 4 && count < 8) {
                firebaseKeyShares.put(count, share.getValue());
            }
            count++;
            if (count >= 12)
                break;
        }

        // Use the saveKeyParts function to store the selected parts across buckets
        firebaseService.saveKeyParts(fbBuckets, user.getId(), firebaseKeyShares);

        // Store key shares in Azure
        AzureBlobService azureBlobService = new AzureBlobService();
        count = 0;
        for (Map.Entry<Integer, byte[]> share : keyShares.entrySet()) {
            if (count >= 8 && count < 12) {
                String azureContainer = "bucket-chats" + (count - 7);
                azureBlobService.uploadMessage(azureContainer, "KEYS/" + this.values[0],
                        new ByteArrayInputStream(share.getValue()));
            }
            count++;
        }
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------KILLING-CLIENT-PROCESS---------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Function that deals with the all process of killing the client
     * 
     * @param peer The peer instance to get the global values.
     * @throws IOException If an I/O error occurs during the killing operations.
     */
    public void killClient(Peer peer) throws IOException {
        User user = new User(peer.values[0], null, 0000, null, null, null);
        sendMessageToServer(user);
        peer.serverThread.closeServerSocket(); // Closes server socket
        deleteSecureFiles(peer);
        clearMessageHistory();
    }

    /**
     * Deletes all the secure files of this user.
     * 
     * @param peer The peer instance used to get the filenames.
     */
    private static void deleteSecureFiles(Peer peer) {
        // Deletion of KeyStore
        File keyStore = new File(peer.keyStoreFile);
        keyStore.delete();

        // Deletion of TrustStore
        File trustStore = new File(peer.trustStoreFile);
        trustStore.delete();
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ------------------------------------------------PROGRAM-LIFECYCLE-MANAGEMENT-------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Adds a shutdown hook to the runtime to handle cleanup when the program is
     * terminated.
     *
     * @param peer The peer instance to get the global values.
     */
    private static void addShutdownHook(Peer peer) {
        // Register a new thread to be executed on program shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                peer.killClient(peer);
            } catch (IOException e) {
                e.printStackTrace();
            }
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

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------AUXILIARY-FUNCTIONS------------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * This method accepts IPv4 addresses in the standard format (xxx.xxx.xxx.xxx),
     * where each "xxx" is a number between 0 and 255, in addition to the value
     * "localhost".
     *
     * @param ip The string representing the IP address to be validated.
     * @return true if the IP address is valid or if it is "localhost";
     *         false otherwise.
     */
    private static boolean isValidIP(String ip) {

        if (ip.equals("localhost"))
            return true;

        String ipRegex = "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

        return ip.matches(ipRegex);
    }

    /**
     * Finds a user by their ID from the list of users in the server.
     * 
     * @param id The ID of the user to find.
     */
    public void findReceiver(String id) {
        User receiverUser = new User(this.user.getId(), null, 0000, id, null, null);
        sendMessageToServer(receiverUser);
    }

    /**
     * Serializes a User object into a byte array for transmission.
     *
     * @param User The User object to be serialized.
     * @return A byte array representing the serialized User.
     * @throws IOException If an error occurs during serialization.
     */
    private static byte[] serializeUser(User user) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        // Serialize the User object into a byte array
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {
            objectOutputStream.writeObject(user); // Serializes object User
        }

        return byteArrayOutputStream.toByteArray(); // Return the byte array
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------MESSAGES-MANAGEMENT------------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    public List<Message> getMessageHistory() {
        return new ArrayList<>(messageHistory); // Returns a copy to prevent external modifications
    }

    public void clearMessageHistory() {
        messageHistory.clear();
    }

    public void addMessageToHistory(Message message) {
        messageHistory.add(message);
    }

    public List<Message> getMessagesByUser(String userId) {
        return messageHistory.stream()
                .filter(msg -> msg.getSender().getId().equals(userId) || msg.getReceiver().getId().equals(userId))
                .collect(Collectors.toList());
    }
    // -----------------------------------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------GETTERS-AND-SETTERS------------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Gets the values of the peer.
     *
     * @return The values of the peer.
     */
    public String[] getValues() {
        return values;
    }

    /**
     * Gets the interests of the peer.
     *
     * @return The interests of the peer.
     */
    public List<String> getInterests() {
        return interests;
    }

    /**
     * Changes the interests of a User.
     *
     * @param interests The interests updated to change.
     */
    public void setInterests(List<String> interests) {
        user.setInterests(interests);
        this.interests = interests;
        User userToSend = new User(this.user.getId(), this.user.getIp(), 0000, null, this.user.getCertificate(),
                this.user.getInterests());
        sendMessageToServer(userToSend);
    }

    /**
     * Gets the VerificationStatus of the peer.
     *
     * @return The VerificationStatus of the peer.
     */
    public boolean getVerificationStatus() {
        return verificationStatus;
    }

    /**
     * Sets the VerificationStatus of the peer.
     */
    public static void setVerificationStatus(Peer peer, boolean bool) {
        peer.verificationStatus = bool;
    }

    /**
     * Gets the RepeatedId of the peer.
     *
     * @return The RepeatedId of the peer.
     */
    public boolean getRepeatedId() {
        return repeatedId;
    }

    /**
     * Sets the RepeatedId of the peer.
     */
    public static void setRepeatedId(Peer peer, boolean bool) {
        peer.repeatedId = bool;
    }

    /**
     * Gets the RepeatedPort of the peer.
     *
     * @return The RepeatedPort of the peer.
     */
    public boolean getRepeatedPort() {
        return repeatedPort;
    }

    /**
     * Sets the RepeatedPort of the peer.
     */
    public static void setRepeatedPort(Peer peer, boolean bool) {
        peer.repeatedPort = bool;
    }

    /**
     * Sets the GroupKeys of the peer.
     */
    public void setGroupKeys(Peer peer, Map<String, Key> groupKeys) {
        peer.groupKeys = groupKeys;
        for (Map.Entry<String, Key> entry : groupKeys.entrySet()) {
            System.out.println("Interest: " + entry.getKey() + " | Key: " + entry.getValue());
        }
    }
}
