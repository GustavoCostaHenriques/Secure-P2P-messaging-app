package com.p2pmessagingapp;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ObjectOutputStream;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

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
    private PeerServer serverThread; // Thread for the peer server
    private boolean verificationStatus = true; // Boolean that checks the values of this peer
    private boolean repeatedId = false; // Boolean that checks the values of this peer
    private boolean repeatedPort = false; // Boolean that checks the values of this peer
    private User user; // User that will be created for this peer
    private final String serverIp = "localhost"; // IP of the server that has information about other peers
    private final int serverPort = 2222; // Port of the server that has information about other peers
    private volatile String serverResponse; // Using 'volatile' on serverResponse to ensure visibility across threads
                                            // and prevent infinite loop due to caching issues
    private volatile User userFound; // Using 'volatile' on serverResponse to ensure visibility across threads and
                                     // prevent infinite loop due to caching issues

    /**
     * The startPeer method serves as the entry point for the P2P messaging
     * application.
     * It prompts the user for their ID and port, verifies the input, starts the
     * peer server, and facilitates communication with other peers.
     *
     * @param args Arguments received from the submissionForm in the PeerController.
     * @throws Exception If an error occurs during initialization or communication.
     */
    public void startPeer(String[] args) throws Exception {
        // Add a shutdown hook to delete client and port files/directories upon exiting
        addShutdownHook(this); // Triggered by pressing 'Control + C'

        for (int i = 0; i < 3; i++) {
            this.values[i] = args[i];
        }

        serverThread = new PeerServer(Integer.parseInt(this.values[1]));

        if (!serverThread.getServerCreated()) {
            setRepeatedPort(this, true);
            setVerificationStatus(this, false);
        }

        if (!isValidIP(this.values[2])) {
            setVerificationStatus(this, false);
        }

        if (this.verificationStatus) {
            serverThread.start();

            sslSocket = createSSLSocket(this.values[2], Integer.parseInt(this.values[1])); // Socket to
                                                                                           // communicate with
                                                                                           // other peers.
            sslServerSocket = createSSLSocket(serverIp, serverPort); // Socket to
                                                                     // communicate
                                                                     // with the
                                                                     // server.
            user = new User(this.values[0], this.values[2], Integer.parseInt(this.values[1]), null);
            sendMessageToServer(user);

            // Wait for the server response
            serverResponse = serverThread.getContentFromTheServer();
            while (serverResponse == null) {
                serverResponse = serverThread.getContentFromTheServer();
            }
            if (serverResponse.equals("1-error")) {
                System.out.println("Id já em uso");
                setVerificationStatus(this, false);
                setRepeatedId(this, true);
                serverThread.closeServerSocket();
            }
            serverThread.setContentFromTheServer(null);
            // Keep the program running indefinitely
            keepProgramRunning();
        } else {
            if (serverThread.getServerCreated())
                serverThread.closeServerSocket();
        }
    }

    /**
     * Constructs a Peer instance and initializes user attributes.
     *
     * @param id   The ID of the user.
     * @param port The port number to be used for communication.
     * @throws Exception If an error occurs during initialization.
     */
    public Peer(String id, String ip, int port) throws Exception {
        this.values[0] = id;
        this.values[1] = String.valueOf(port);
        this.values[2] = ip;
        this.sslSocket = createSSLSocket(ip, port);
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
     * Asks the user for the ID of the peer they want to communicate with.
     * 
     * @param otherPeerID Id of the peer we want to communicate with.
     * @return The User that the server sends (this user can have the id equal to
     *         "NULL" meaning that the user was not found).
     */
    public User checkscommunication(String otherPeerID) throws Exception {

        User receiverUser = new User(values[0], null, 0000, otherPeerID);
        sendMessageToServer(receiverUser);

        // Wait for the server response
        userFound = serverThread.getUserSearched();
        while (userFound == null) {
            userFound = serverThread.getUserSearched();
        }

        System.out.println("Saiu do ciclo");

        serverThread.setUserSearched(null);

        return userFound;
    }

    /**
     * Handles the communication between users.
     *
     * @param receiver The user to communicate with.
     * @param content  The content of the message that is going to be sent.
     */
    public void communicate(User receiver, String content) {
        System.out.println("User id: " + receiver.getId());

        createChatDir();
        String filename = createChat(this.values[0], receiver.getId());

        // Create a message and send it to the receiver
        Message message = new Message(user, receiver, content, filename);

        try {
            this.serverThread.sendMessage(message); // Send the message through the server thread
        } catch (Exception e) {
        }
    }

    /**
     * Sends a serialized message through the secure socket.
     *
     * @param serializedMessage The message to be sent in byte array format.
     */
    public void sendMessage(byte[] serializedMessage) {
        try (OutputStream outputStream = sslSocket.getOutputStream()) {
            // Send the serialized message bytes through the OutputStream
            outputStream.write(serializedMessage);
            outputStream.flush(); // Ensure the message is sent immediately
        } catch (IOException e) {
        }
    }

    /**
     * Sends a serialized user through the secure server socket.
     * 
     * @param user The user to be serialized and sent.
     */
    private void sendMessageToServer(User user) {
        if (sslServerSocket == null || sslServerSocket.isClosed())
            sslServerSocket = createSSLSocket(serverIp, serverPort);
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
    // ---------------------------------------------USER-MANAGEMENT-AND-SSLSOCKET-SETUP---------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Creates an SSL socket for secure communication with the specified ip address
     * and port.
     *
     * @param ip   The ip address to connect to.
     * @param port The port number to connect to.
     * @return socket The socket that the peer wants to create.
     */
    private static SSLSocket createSSLSocket(String ip, int port) {
        SSLSocket socket = null;
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.2");
            KeyManagerFactory keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keys = KeyStore.getInstance("JKS");
            try (InputStream stream = new FileInputStream("stream.jks")) {
                keys.load(stream, "p2pmessagingapp".toCharArray());
            }
            keyManager.init(keys, "p2pmessagingapp".toCharArray());

            KeyStore store = KeyStore.getInstance("JKS");
            try (InputStream storeStream = new FileInputStream("storestream.jks")) {
                store.load(storeStream, "p2pmessagingapp".toCharArray());
            }

            TrustManagerFactory trustManager = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManager.init(store);

            context.init(keyManager.getKeyManagers(), trustManager.getTrustManagers(), null);
            SSLSocketFactory factory = context.getSocketFactory();
            socket = (SSLSocket) factory.createSocket(ip, port);
            System.out.println("Criou o socket");

        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException
                | CertificateException | KeyManagementException e) {
        }
        return socket;
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ----------------------------------------------CHAT-DIRECTORY-MANAGEMENT-METHODS----------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Utility method to create the "chats" directory if it doesn't already exist.
     * This directory is used to store chat history files.
     */
    private static void createChatDir() {
        try {
            File dir = new File("chats"); // Create a reference to the "chats" directory
            if (!dir.exists()) { // Check if the directory doesn't exist
                dir.mkdir(); // Create the directory
            }
        } catch (Exception e) {
            // Handle exception silently (could log error if necessary)
        }
    }

    /**
     * Creates a new chat file between two users, if it doesn't already exist.
     * Checks both possible name combinations for the chat file (user1-user2 and
     * user2-user1), ensuring that only one file is created for a conversation
     * between two users.
     *
     * @param user1 The first user's ID.
     * @param user2 The second user's ID.
     * @return The name of the chat file that exists or was created, or null if an
     *         error occurred.
     */
    private static String createChat(String user1, String user2) {
        try {
            // File path in the format "chats/user1-user2"
            String name = "chats/" + user1 + "-" + user2;
            // Alternative file path in the format "chats/user2-user1"
            String othername = "chats/" + user2 + "-" + user1;

            File chat = new File(name); // Create a reference to the first possible chat file
            File otherChat = new File(othername); // Create a reference to the second possible chat file

            // If neither chat file exists, create the first one
            if (!chat.exists() && !otherChat.exists()) {
                chat.createNewFile(); // Create the chat file with name user1-user2
            }

            // Return the name of the file that exists
            if (chat.exists()) {
                return name; // Return user1-user2 if it exists
            } else if (otherChat.exists()) {
                return othername; // Return user2-user1 if it exists
            }
        } catch (Exception e) {
            // Handle exception silently (could log error if necessary)
        }
        return null; // Return null if no chat file could be created or found
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------KILLING-CLIENT-PROCESS---------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Functions that deals with the all process of killing the client
     * 
     * @param peer The peer instance to get the global values.
     * @throws IOException If an I/O error occurs during the killing operations.
     */
    public void killClient(Peer peer) throws IOException {
        System.out.println("Chegou aqui");
        deleteMessageFile(peer);
        User user = new User(peer.values[0], null, 0000, null);
        sendMessageToServer(user);
        peer.serverThread.closeServerSocket(); // Closes server socket
        System.out.println("Fechou o server");
    }

    /**
     * Deletes all the necessary message files. It checks if the corresponding peer
     * (user) is offline and, if so, deletes the message files related to that peer.
     * After processing all files, if the "chats" directory is empty, it deletes the
     * directory.
     * 
     * @param peer The peer instance used to get the global values (e.g., the
     *             current user's name).
     */
    private static void deleteMessageFile(Peer peer) {
        // Define the "chats" folder where message files are stored
        File chatsFolder = new File("chats");

        // Array to hold the list of files in the "chats" directory
        File[] chatsFiles;

        // Check if the "chats" directory exists and is a directory
        if (chatsFolder.exists() && chatsFolder.isDirectory()) {
            // Get the list of files inside the "chats" directory
            chatsFiles = chatsFolder.listFiles();

            // If the directory contains files (non-null), process them
            if (chatsFiles != null) {
                // Loop through each file in the "chats" directory
                for (File chatsFile : chatsFiles) {
                    // Ensure that the current item is a file and not a subdirectory
                    if (chatsFile.isFile()) {
                        // Extract the names of the users involved in the chat from the filename
                        String[] usersNames = chatsFile.getName().split("-");
                        String otherUser = null;

                        // Determine which user is the other participant in the chat
                        if (peer.values[0].equals(usersNames[0])) {
                            otherUser = usersNames[1]; // If the current peer is the first user, set the other user
                        } else if (peer.values[0].equals(usersNames[1])) {
                            otherUser = usersNames[0]; // If the current peer is the second user, set the other user
                        }

                        // Flag to check if the other user (client) is online
                        User clientIsOnline = null;

                        try {
                            clientIsOnline = peer.checkscommunication(otherUser);
                        } catch (Exception e) {
                        }
                        while (clientIsOnline == null) {
                            try {
                                Thread.sleep(1000); // Waits for 1 second (1000 milliseconds)
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                        }

                        if (clientIsOnline.getId().equals("NULL"))
                            chatsFile.delete(); // Delete the chat file for the offline user
                    }
                }
            }
        }

        // After processing all files, check if the "chats" directory is now empty
        chatsFiles = chatsFolder.listFiles(); // Refresh the file list after deletions
        if (chatsFiles != null && chatsFiles.length == 0) {
            chatsFolder.delete(); // Delete the "chats" directory if no files remain
        }
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
            deleteMessageFile(peer);
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

        if (ip.equals("localhost")) {
            return true;
        }

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
        User receiverUser = new User(this.user.getId(), null, 0000, id);
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
    // ----------------------------------------------------GETTERS-AND-SETTERS------------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Gets the VerificationStatus of the peer.
     *
     * @return The VerificationStatus of the peer.
     */
    public String[] getValues() {
        return values;
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

}