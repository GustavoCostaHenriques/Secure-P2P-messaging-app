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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.*;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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
import org.apache.tomcat.util.http.fileupload.ByteArrayOutputStream;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.SdkClientException;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.codahale.shamir.Scheme;
import com.google.cloud.firestore.CollectionReference;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.QueryDocumentSnapshot;
import com.google.firebase.cloud.FirestoreClient;

import io.github.cdimascio.dotenv.Dotenv;

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
    private final List<Message> messageHistory = new CopyOnWriteArrayList<>(); // List to store all individual messages
                                                                               // for this
                                                                               // peer
    private final List<Message> messageGroupHistory = new CopyOnWriteArrayList<>(); // List to store all group messages
                                                                                    // for this
    // peer
    private PeerServer serverThread; // Thread for the peer server
    private boolean verificationStatus = true; // Boolean that checks the values of this peer
    private boolean repeatedId = false; // Boolean that checks the values of this peer
    private boolean repeatedPort = false; // Boolean that checks the values of this peer
    private User user; // User that will be created for this peer
    private final String serverIp = "localhost"; // IP of the server that has information about other peers
    private final int serverPort = 2222; // Port of the server that has information about other peers
    private boolean firstMessageSent = true; // Bool that checks if it's the first message that this peer is sending to
                                             // the cloud.
    private SecretKey aesKey; // Secret Key of the peer to encrypt messages to store in the cloud.
    private int NumberOfKeysFound = 1; // Integer to know how many key parts this peer found.
    private Map<Integer, byte[]> keyParts = new HashMap<>(); // HashMap to store the 8 parts necessary to reconstruct
                                                             // the key.
    private Scheme scheme = new Scheme(new SecureRandom(), 12, 8); // 12 parts to divide the key, minimum of 8 to
                                                                   // reconstruct.
    private volatile User userFound; // Using 'volatile' on serverResponse to ensure visibility across threads and
                                     // prevent infinite loop due to caching issues,
    private Key groupKey;
    private List<User> allUsers;
    // Variables that will store the paths for the keystore, truststore and server
    // certificate.
    private String keyStoreFile;
    private String trustStoreFile;
    private String serverCertFile;
    private String password; // Password of this user, to manage the security of keystore and truststore.
    private X509Certificate cert; // Certificate of this user.

    private final String[] interestsDefault = { // All the existing interests.
            "Technology", "Sports and Fitness", "Travel", "Music", "Movies and TV",
            "Reading and Literature", "Health and Wellness", "Food and Cooking", "Nature and Sustainability",
            "Art and Culture", "Science and Innovation", "History", "Animals and Pets", "Personal Development",
            "Gaming and Entertainment", "Fashion and Style", "Politics and Society", "Photography",
            "Spirituality and Meditation", "Education and Learning"
    };

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

        for (String interest : this.interestsDefault) {
            if (this.values[0].equals(interest)) {
                setVerificationStatus(this, false); // Mark verification as failed
                setRepeatedId(this, true); // Indicate duplicate ID found (in this case on ID is duplicate but the user
                                           // can't have the name of an interest)
            }
        }

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
        generatePeerKeyStore("peerAlias", password, keyStoreFile); // To store the keyPair and the certificate
        generateTrustStore(trustStoreFile, password); // Certificates of ther other Peers and Server

        // Add server certificate to peer's TrustStore for trusted communication
        addServerCertToPeerTrustStore(trustStoreFile, password, serverCertFile);

        // Create a User object with peer's details (for later communication)
        user = new User(this.values[0], this.values[2], Integer.parseInt(this.values[1]), null, cert, interests, null);

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

            String objectKey = "KEYS/" + this.values[0];
            this.searchMessage(null, objectKey);
            if (!firstMessageSent) {
                objectKey = "CHATS/" + this.values[0];
                List<Message> messagesFound = this.searchMessage("NULL", objectKey);

                for (Message message : messagesFound) {
                    if (message.getBroadcastMsg())
                        this.addMessageGroupToHistory(message);
                    else
                        this.addMessageToHistory(message);
                }
            }

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
        user = new User(this.values[0], this.values[2], Integer.parseInt(this.values[1]), null, cert, interests, null);

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
     * @param sendingMsg  Boolean to know if we are checking a user to send a
     *                    message or simply to see if the user exists.
     *
     * @return The User that the server sends (this user can have the id equal to
     *         "NULL" meaning that the user was not found).
     */
    public User checkscommunication(String otherPeerID, boolean sendingMsg) throws Exception {

        User receiverUser = new User(values[0], null, 0000, otherPeerID, null, null, null);
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

        if (userFound.getId().equals("NULL") && !sendingMsg) { // This means that the server didn't found any user
            for (Message message : messageHistory) {
                if (message.getReceiver().getId().equals(otherPeerID)
                        || message.getSender().getId().equals(otherPeerID))
                    userFound = new User(otherPeerID, null, 0000, null, null, null, null);
            }
        }

        return userFound;
    }

    /**
     * Asks the user to encrypt the groupName with the appropriate key.
     *
     * @param groupName The name of the group that the server is going to encrypt.
     * @return The groupName encrypted by the server in a string format.
     */
    public String askToEncryptGroupNameToServer(String groupName) throws InterruptedException {
        User userToSend = new User(this.user.getId(), null, (-2), null, this.user.getCertificate(),
                null, groupName);
        sendMessageToServer(userToSend);

        // Wait for the server response
        String groupNameEncrypted = serverThread.getGroupNameEncrypted();
        while (groupNameEncrypted == null) {
            Thread.sleep(1000);
            groupNameEncrypted = serverThread.getGroupNameEncrypted();
        }

        serverThread.setGroupNameEncrypted(null);

        return groupNameEncrypted;
    }

    /**
     * Handles the communication between users.
     *
     * @param receiver The user to communicate with.
     * @param content  The content of the message that is going to be sent.
     */
    public void communicate(User receiver, String content) {

        // Creates a message
        Message message = new Message(user, receiver, content, false, null);

        try {

            this.serverThread.sendMessage(message); // Send the message through the server thread
            // Add to the message history
            addMessageToHistory(message);

            String objectKey = "CHATS/" + user.getId() + "/Send_" + receiver.getId() + "_" + message.getTime();

            this.sendMessageToCloud(objectKey, content);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Handles the broadcast of a message.
     *
     * @param content   The content of the message that is going to be sent.
     * @param groupName The name of the group that the message is going to be
     *                  broadcasted.
     */
    public void broadcast(String content, String groupName) throws InterruptedException {

        // String encryptedContent = encryptMessageWithABE(content, this.interests);

        for (User receiver : allUsers) {
            // Creates a message
            Message message = new Message(user, receiver, content, true, groupName);

            try {

                this.serverThread.sendMessage(message); // Send the message through the server thread
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        Message message = new Message(user, null, content, true, groupName);

        // Add to the message history
        addMessageGroupToHistory(message);

        String objectKey = "CHATS/" + user.getId() + "/Send_" + groupName + "_" + message.getTime();

        this.sendMessageToCloud(objectKey, content);
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
    // -------------------------------------------------------ABE-ECNRYPTION--------------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Encrypts the message content using ABE based on the user's interests
     * (attributes).
     * This method would apply ABE encryption with a policy based on the user's
     * interests.
     *
     * @param content   The message content to be encrypted.
     * @param interests The interests (or attributes) of the user.
     * @return The encrypted message content.
     */
    /*
     * private String encryptMessageWithABE(String content, List<String> interests)
     * {
     * try {
     * // Example ABE encryption logic:
     * // 1. Generate the ABE policy based on the user's interests (attributes).
     * String policy = generateABEPolicy(interests);
     * 
     * // 2. Encrypt the message using ABE. This involves creating a ciphertext with
     * // the policy.
     * PairingCipherSerParameter encryptedMessage = encryptWithABE(content, policy);
     * 
     * // Convert PairingCipherSerParameter to byte array using serialization
     * try (ByteArrayOutputStream byteArrayOutputStream = new
     * ByteArrayOutputStream();
     * ObjectOutputStream objectOutputStream = new
     * ObjectOutputStream(byteArrayOutputStream)) {
     * objectOutputStream.writeObject(encryptedMessage);
     * objectOutputStream.flush();
     * byte[] byteArray = byteArrayOutputStream.toByteArray();
     * 
     * // Return the encrypted message as a Base64 string
     * return Base64.getEncoder().encodeToString(byteArray);
     * }
     * } catch (Exception e) {
     * e.printStackTrace();
     * return null; // Handle the exception as needed
     * }
     * }
     */

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ------------------------------------------------------MESSAGE-SEARCHING------------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Searches a message in the cloud.
     * 
     * @param messageToBeSearched Content that the user searched.
     * @param path                The path that is going to be searched in the
     *                            cloud.
     * @return The list of the mssages found.
     */
    public List<Message> searchMessage(String messageToBeSearched, String path) {
        List<Message> messagesFound = new ArrayList<>();
        try {
            // List of cloud containers to search in
            String[] awsBuckets = {
                    Dotenv.load().get("S3_BUCKET_NAME_1"),
                    Dotenv.load().get("S3_BUCKET_NAME_2"),
                    Dotenv.load().get("S3_BUCKET_NAME_3"),
                    Dotenv.load().get("S3_BUCKET_NAME_4")
            };

            String[] fbContainers = { "bucket_chats1", "bucket_chats2", "bucket_chats3", "bucket_chats4" };
            String[] azureContainers = { "bucket-chats1", "bucket-chats2", "bucket-chats3", "bucket-chats4" };

            for (int i = 0; i < 3; i++) {

                String cloudService = null;
                String[] containers = null;

                if (i == 0) {
                    cloudService = "AWS";
                    containers = awsBuckets;
                } else if (i == 1) {
                    cloudService = "FIREBASE";
                    containers = fbContainers;
                } else if (i == 2) {
                    cloudService = "AZURE";
                    containers = azureContainers;
                }

                List<Message> CloudMessages = processSearchForEachService(containers, cloudService, messagesFound,
                        messageToBeSearched, path);

                for (Message message : CloudMessages) {
                    messagesFound.add(message);
                    if (path.charAt(0) == 'K' && messagesFound.size() == 8)
                        break;
                }
                if (path.charAt(0) == 'K' && messagesFound.size() == 8)
                    break;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return messagesFound;
    }

    /**
     * Process the search of messages for a specific cloud service (AWS, Firebase,
     * Microsoft).
     * 
     * @param containers           The containers of a specific cloud service.
     * @param cloudService         The cloud service that os going to be searched.
     * @param messagesFoundAlready The messages that were already found.
     * @param messageToBeSearched  The content that the peer is trying to find.
     * @param path                 The path that is going to be searched in the
     *                             cloud.
     * @return A list of new messages found (in case there is any).
     */
    private List<Message> processSearchForEachService(String[] containers, String cloudService,
            List<Message> messagesFoundAlready, String messageToBeSearched, String path) {

        List<Message> messagesFound = new ArrayList<>();

        for (String container : containers) {
            List<String> objectKeys = new ArrayList<>();
            if (cloudService.equals("AWS")) // Fetch all object keys from the AWS bucket for messages.
                objectKeys = getObjectKeysFromAWSS3Bucket(container, path);
            else if (cloudService.equals("FIREBASE")) // Fetch all object keys from the Firebase bucket for messages.
                objectKeys = getObjectKeysFromFirebaseBucket(container, path);
            else if (cloudService.equals("AZURE"))
                objectKeys = getObjectKeysFromAzureBucket(container, path);

            // Loop through each object key and check if it matches the search term
            for (String objectKey : objectKeys) {
                String messageContent = new String();
                if (messageToBeSearched != null)
                    messageContent = fetchAndDecryptMessageFromCloud(container, objectKey, cloudService);
                else {
                    if (NumberOfKeysFound <= 8) {
                        byte[] bytekeyPart = fetchEncryptedContentFromCloud(container, objectKey, cloudService);
                        keyParts.put(NumberOfKeysFound, bytekeyPart);
                        NumberOfKeysFound += 1;
                    }
                    if (NumberOfKeysFound == 9) {
                        byte[] reconstructedKeyBytes = scheme.join(keyParts);

                        aesKey = new SecretKeySpec(reconstructedKeyBytes, 0, reconstructedKeyBytes.length, "AES");
                        firstMessageSent = false;

                        NumberOfKeysFound += 1;
                    }
                }

                if (messageToBeSearched != null) {
                    String[] parts = objectKey.replace(path + "/", "").split("_");

                    Message message = buildMessage(parts, messageContent);

                    // If message contains the searched text, add it to the result
                    if ((message != null && messageContent.contains(messageToBeSearched))
                            || (message != null && messageToBeSearched.equals("NULL"))) {
                        boolean messageExists = false;
                        for (Message singleMessage : messagesFoundAlready) {
                            if (message.equals(singleMessage)) // Checks if the message was already found
                                messageExists = true;
                        }
                        for (Message singlMessage : messagesFound) {
                            if (message.equals(singlMessage))
                                messageExists = true;
                        }
                        if (!messageExists) {
                            messagesFound.add(message);
                        }
                    }
                }

            }
        }

        return messagesFound;
    }

    /**
     * Fetches and decrypts the message content from the cloud (AWS, Firebase, or
     * Azure).
     * 
     * @param container    The container from which to fetch the message.
     * @param objectKey    The object key that identifies the specific message.
     * @param cloudService The service that we are searching.
     * @return The decrypted message content.
     */
    private String fetchAndDecryptMessageFromCloud(String container, String objectKey, String cloudService) {
        try {
            // Fetch the encrypted content from the cloud storage (AWS, Firebase, Azure)
            byte[] encryptedContent = fetchEncryptedContentFromCloud(container, objectKey, cloudService);

            // Decrypt the content
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] decryptedContent = cipher.doFinal(encryptedContent);

            // Convert decrypted byte array to string
            return new String(decryptedContent, StandardCharsets.UTF_8);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Fetches encrypted content from Firebase Storage.
     *
     * @param container The Firebase bucket name.
     * @param objectKey The object key identifying the message.
     * @return A byte array containing the encrypted content, or null if an error
     *         occurs.
     */
    private byte[] fetchEncryptedContentFromCloud(String container, String objectKey, String cloudService) {
        if (cloudService.equals("AWS")) {
            try {
                // Fetch the object from AWS S3
                S3Object s3Object = S3Config.s3Client.getObject(new GetObjectRequest(container, objectKey));

                // Read the content into a byte array
                InputStream inputStream = s3Object.getObjectContent();
                byte[] content = inputStream.readAllBytes();
                inputStream.close();

                return content;
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else if (cloudService.equals("FIREBASE")) {
            try {
                // Access Firestore database
                Firestore db = FirestoreClient.getFirestore();

                // Fetch the document from Firestore
                DocumentSnapshot document = db.collection(container).document(objectKey).get().get();

                if (document.exists()) {
                    // Retrieve the content field from the document
                    String base64Content = document.getString("content");

                    if (objectKey.charAt(0) == 'K')
                        base64Content = document.getString("keyPart");

                    if (base64Content != null) {
                        // Decode Base64 content into a byte array
                        return Base64.getDecoder().decode(base64Content);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else if (cloudService.equals("AZURE")) {
            try {
                // Access the Azure Blob Storage service
                AzureBlobService azureBlobService = new AzureBlobService();

                // Fetch the blob content
                return azureBlobService.fetchBlobContent(container, objectKey);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    /**
     * Retrieves all object keys from the AWS S3 buckets that match the pattern
     * for a specific user.
     * 
     * @param bucket The specific bucket that we are .
     * @param path   The path that is going to be searched in the cloud.
     * @return List of object keys that belong to the user.
     */
    public List<String> getObjectKeysFromAWSS3Bucket(String bucket, String path) {

        List<String> objectKeys = new ArrayList<>();
        String userPrefix = path + "/"; // Prefix pattern for the current user.

        if (path.charAt(0) == 'K')
            userPrefix = path;

        try {
            // List objects in the current bucket with the specified prefix
            ObjectListing objectListing = S3Config.s3Client.listObjects(bucket, userPrefix);
            List<S3ObjectSummary> summaries = objectListing.getObjectSummaries();

            for (S3ObjectSummary summary : summaries) {
                objectKeys.add(summary.getKey()); // Add the object key to the result list
            }

            // Handle pagination in case there are too many objects for a single response
            while (objectListing.isTruncated()) {
                objectListing = S3Config.s3Client.listNextBatchOfObjects(objectListing);
                summaries = objectListing.getObjectSummaries();

                for (S3ObjectSummary summary : summaries) {
                    objectKeys.add(summary.getKey());
                }
            }
        } catch (AmazonServiceException e) {
            System.err.println("Error communicating with AWS S3: " + e.getMessage());
            e.printStackTrace();
        } catch (SdkClientException e) {
            System.err.println("SDK error when accessing AWS S3: " + e.getMessage());
            e.printStackTrace();
        }

        return objectKeys;
    }

    /**
     * Retrieves all object keys from a Firebase Storage bucket that match a
     * specific user's prefix.
     *
     * @param bucket The Firebase Storage bucket name.
     * @param path   The path that is going to be searched in the cloud.
     * @return List of object keys belonging to the user.
     */
    public List<String> getObjectKeysFromFirebaseBucket(String bucketName, String path) {
        List<String> objectKeys = new ArrayList<>();
        String userPrefix = bucketName + "/" + path; // Specific prefix of the user.

        try {
            // Reference to the collection in Firestore
            FirebaseService firebaseService = new FirebaseService();
            Firestore db = firebaseService.getDb();
            CollectionReference collectionRef = db.collection(userPrefix);

            // Fetch all documents in the collection
            List<QueryDocumentSnapshot> documents = collectionRef.get().get().getDocuments();

            for (DocumentSnapshot doc : documents) {
                String objectKey = doc.getId(); // Use the document ID as the object key
                String finalObjectKey = path + "/" + objectKey;
                objectKeys.add(finalObjectKey); // Add to the list only if it matches the prefix
            }
        } catch (Exception e) {
            System.err.println("Erro ao acessar Firebase Storage: " + e.getMessage());
            e.printStackTrace();
        }
        return objectKeys;
    }

    /**
     * Retrieves all object keys from a Firebase Storage bucket that match a
     * specific user's prefix.
     *
     * @param bucket The Firebase Storage bucket name.
     * @param path   The path that is going to be searched in the cloud.
     * @return List of object keys belonging to the user.
     */
    public List<String> getObjectKeysFromAzureBucket(String bucketName, String path) {
        List<String> objectKeys = new ArrayList<>();
        String userPrefix = path + "/";

        if (path.charAt(0) == 'K')
            userPrefix = path;

        AzureBlobService azureBlobService = new AzureBlobService();
        objectKeys = azureBlobService.listBlobsInDirectory(bucketName, userPrefix);
        return objectKeys;
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ------------------------------------------------CLOUD-STORAGE-UNITS-MANAGEMENT-----------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    public void sendMessageToCloud(String objectKey, String content) {

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
                Map<Integer, byte[]> keyShares = scheme.split(aesKey.getEncoded());

                storeKeyShares(keyShares);
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

    private void storeKeyShares(Map<Integer, byte[]> keyShares) {
        int count = 0;

        // Store key shares in AWS
        for (Map.Entry<Integer, byte[]> share : keyShares.entrySet()) {
            if (count < 4) {
                String awsBucket = Dotenv.load().get("S3_BUCKET_NAME_" + (count + 1));

                ObjectMetadata keyMetadata = new ObjectMetadata();
                keyMetadata.setContentLength(share.getValue().length);
                keyMetadata.addUserMetadata("keyPart", String.valueOf(count));

                S3Config.s3Client.putObject(new PutObjectRequest(awsBucket, "KEYS/" + this.values[0],
                        new ByteArrayInputStream(share.getValue()), keyMetadata));
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
        User user = new User(peer.values[0], null, 0000, null, null, null, null);
        sendMessageToServer(user);
        peer.serverThread.closeServerSocket(); // Closes server socket
        deleteSecureFiles(peer);
        clearMessageHistory();
        clearMessageGroupHistory();
        peer.interests = null;
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
        User receiverUser = new User(this.user.getId(), null, 0000, id, null, null, null);
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

    /**
     * Builds a message with the information received from the cloud.
     *
     * @param parts          A list of strings to build the message.
     * @param messageContent The content to store in a message.
     * @return A message.
     */
    private Message buildMessage(String[] parts, String messageContent) {

        boolean groupMessage = false;
        Message message = null;

        if (parts.length == 3) { // Individual messages or messages sent in a group
            String direction = parts[0];
            String otherPeer = parts[1];
            User otherUser = new User(otherPeer, null, 0, null, null, null, null);
            String time = parts[2];
            if (direction.equals("Send")) {
                for (String interest : this.interestsDefault) {
                    if (otherPeer.equals(interest)) { // this means that we found a group message sent by
                                                      // this peer
                        message = new Message(user, null, messageContent, true, otherPeer);
                        message.setTime(time);
                        groupMessage = true;
                    }
                }
                if (!groupMessage) {
                    message = new Message(user, otherUser, messageContent, false, null);
                    message.setTime(time);
                }

            } else {
                message = new Message(otherUser, user, messageContent, false, null);
                message.setTime(time);
            }
        }

        else if (parts.length == 4) { // Messages received in a group
            String direction = parts[0];
            String otherPeer = parts[1];
            User otherUser = new User(otherPeer, null, 0, null, null, null, null);
            String groupName = parts[2];
            String time = parts[3];
            if (direction.equals("Send")) {
                message = new Message(user, otherUser, messageContent, true, groupName);
                message.setTime(time);
            } else {
                message = new Message(otherUser, user, messageContent, true, groupName);
                message.setTime(time);
            }
        }

        return message;
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

    public List<Message> getMessageGroupHistory() {
        return new ArrayList<>(messageGroupHistory); // Returns a copy to prevent external modifications
    }

    public void clearMessageGroupHistory() {
        messageGroupHistory.clear();
    }

    public void addMessageGroupToHistory(Message message) {
        messageGroupHistory.add(message);
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
                this.user.getInterests(), null);
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
     * Gets the groupKey of the peer.
     *
     * @return The groupKey of the peer.
     */
    public Key getGroupKey() {
        return this.groupKey;
    }

    /**
     * Sets the GroupKey of the peer.
     */
    public void setGroupKey(Peer peer, Key groupKey) {
        peer.groupKey = groupKey;
    }

    /**
     * Gets all the Users that exist.
     *
     * @return All users.
     */
    public List<User> getAllUsers() throws Exception {

        User userToSend = new User(this.user.getId(), null, (-1), null, this.user.getCertificate(),
                null, null);
        sendMessageToServer(userToSend);

        allUsers = serverThread.getAllUsers();
        while (allUsers == null) {
            allUsers = serverThread.getAllUsers();
        }

        serverThread.setAllUsers(null);

        for (User simpleUser : allUsers) {
            // If the user was found, add their certificate to this peer's TrustStore
            if (!simpleUser.getId().equals("NULL") && simpleUser.getCertificate() != null)
                // Add the certificate of the found peer to the TrustStore for secure
                // communication
                addPeerCertificateToTrustStore(simpleUser, trustStoreFile, password);
        }

        return allUsers;
    }
}