package com.p2pmessagingapp;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * The Peer class represents a peer in the P2P messaging application.
 * It handles user interaction, manages the peer server, and facilitates
 * communication between users.
 */
public class Peer {

    private SSLSocket sslSocket; // SSL socket for secure communication
    private String[] values = new String[3]; // Array to hold user input values (ID, port and IP)
    private PeerServer serverThread; // Thread for the peer server
    private final static List<User> Users = new ArrayList<>(); // Creates a list of users
    private boolean verificationStatus; // Boolean that checks the values of this peer
    private boolean repeatedId; // Boolean that checks the values of this peer
    private boolean repeatedPort; // Boolean that checks the values of this peer

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

        setRepeatedId(this, false); // In each cycle we assume that the ID is going to be valid
        setRepeatedId(this, false); // In each cycle we assume that the Port is going to be valid

        this.verificationStatus = fileAndPortVerification(this); // Verify input values

        setVerificationStatus(this, this.verificationStatus);
        if (this.verificationStatus) {
            // Start the peer server on the specified port
            this.serverThread = new PeerServer(Integer.parseInt(this.values[1]));
            this.serverThread.start();

            // Create user attributes based on user input
            createUserAtributtes(this, this.values[0], this.values[2], Integer.parseInt(this.values[1]));

            // Prompt the user for a peer to communicate with
            // askForcommunication(this, this.bufferedReader, this.values[0],
            // this.serverThread);
            // Keep the program running indefinitely
            keepProgramRunning();
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
        createUserAtributtes(this, id, ip, port); // Create user attributes for a new peer
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
     * @param peer           The peer instance to get the global values.
     * @param bufferedReader The BufferedReader to read input from the user.
     * @param id             The ID of the current user.
     * @param serverThread   The thread handling server operations.
     * @throws Exception If an error occurs during the communication setup.
     */
    private static void askForcommunication(Peer peer, BufferedReader bufferedReader, String id,
            PeerServer serverThread)
            throws Exception {

        // Prompt the user to enter the ID of the peer they want to communicate with
        System.out.println(
                "=> Please enter the ID of the person you want to communicate with below ('%% exit' to exit):");
        String otherPeerID;
        User receiverUser = null;

        // Continuously prompt for input until a valid ID is provided or the user opts
        // to exit
        while (true) {
            // Read the ID entered by the user
            otherPeerID = bufferedReader.readLine();

            // Check if the user wants to exit the communication
            if (otherPeerID.equals("%% exit")) {
                peer.killClient(peer);
                peer.startPeer(peer.values);
            }

            // Update the list of active peers
            updateActivePeers();

            // Find the user associated with the entered ID
            receiverUser = findReceiver(otherPeerID);

            // If no user is found, prompt for a different ID
            if (receiverUser == null) {
                System.out.println("=> Invalid ID, please insert a different ID ('%% exit' to exit):");
            } else {
                // A valid receiver has been found, exit the loop
                break;
            }
        }

        // Start communication with the identified user
        communicate(peer, bufferedReader, id, serverThread, receiverUser, peer.sslSocket);
    }

    /**
     * Handles the communication between users.
     *
     * @param peer           The peer instance to get the global values.
     * @param bufferedReader The BufferedReader to read messages from the user.
     * @param id             The ID of the current user.
     * @param serverThread   The thread handling server operations.
     * @param receiver       The user to communicate with.
     * @param sslSocket      The secure socket for communication.
     */
    private static void communicate(Peer peer, BufferedReader bufferedReader, String id, PeerServer serverThread,
            User receiver,
            SSLSocket sslSocket) {

        createChatDir();
        String filename = createChat(id, receiver.getId());
        try {
            // Inform the user that communication can now begin
            System.out.println("=>You can now communicate ('%% exit' to exit, '%% change' to change)");

            OUTER: while (true) {
                // Read user input for the message
                String content = bufferedReader.readLine();
                switch (content) {
                    case "%% exit":
                        // Exit the communication
                        peer.killClient(peer);
                        break OUTER; // Break out of the loop
                    case "%% change":
                        // Change the peer for communication
                        Users.clear();
                        askForcommunication(peer, bufferedReader, id, serverThread); // Prompt for a new peer
                        break;
                    default:
                        // Create a message and send it to the receiver
                        Message message = new Message(Users.get(0), receiver, content, filename);
                        serverThread.sendMessage(message); // Send the message through the server thread
                        break;
                }
            }
            peer.startPeer(peer.values); // Return to the start peer interface
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

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ---------------------------------------------USER-MANAGEMENT-AND-SSLSOCKET-SETUP---------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Creates user attributes by initializing necessary files and SSL socket.
     *
     * @param peer The peer instance to get the global values.
     * @param id   The id of the user.
     * @param ip   The ip address of the user.
     * @param port The port number associated with the user.
     */
    private static void createUserAtributtes(Peer peer, String id, String ip, int port) {
        createPortsFile(port);
        createSSLSocket(peer, ip, port);
        createClientFile(id, ip, port);
        createUser(id, ip, port);
    }

    /**
     * Creates a file to store port information if it does not already exist.
     *
     * @param port The port number to be written to the file.
     */
    private static void createPortsFile(int port) {
        boolean alreadyExists = false;
        for (User user : Users) { // Checks if the port is already written in the Ports file
            if (user.getPort() == port)
                alreadyExists = true;
        }
        File portFile;
        if (!alreadyExists) {
            try {
                portFile = new File("Ports");
                portFile.createNewFile();
                BufferedWriter writer;
                try (Scanner sc = new Scanner(portFile)) {
                    writer = new BufferedWriter(new FileWriter(portFile, true)); // append mode
                    while (sc.hasNextLine()) {
                        sc.nextLine();
                    }
                }
                writer.write(String.valueOf(port)); // write the port in the file
                writer.write(System.getProperty("line.separator"));
                writer.close();

            } catch (IOException e) {
            }
        }
    }

    /**
     * Creates an SSL socket for secure communication with the specified ip address
     * and
     * port.
     *
     * @param peer The peer instance to get the global values.
     * @param ip   The ip address to connect to.
     * @param port The port number to connect to.
     */
    private static void createSSLSocket(Peer peer, String ip, int port) {
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
            peer.sslSocket = (SSLSocket) factory.createSocket(ip, port);

        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException
                | CertificateException | KeyManagementException e) {
        }
    }

    /**
     * Creates a client file for the user with the specified ID and writes the port
     * number to it.
     *
     * @param id   The identifier of the user.
     * @param ip   The ip address of the user.
     * @param port The port number to be written in the client file.
     */
    private static void createClientFile(String id, String ip, int port) {
        try {
            File dir = new File("clients");
            if (!dir.exists()) {
                dir.mkdir(); // Create the directory if it does not exist
            }

            File file = new File(dir, id);
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                writer.write(String.valueOf(port)); // write the port in the file
                writer.write(System.getProperty("line.separator"));
                writer.write(ip);
            } // write the port in the file

        } catch (IOException e) {
            // Handle the exception appropriately
        }
    }

    /**
     * Creates a new user with the specified ID and port if the user does not
     * already exist.
     *
     * @param id   The identifier of the user.
     * @param ip   The ip address of the user.
     * @param port The port number associated with the user.
     */
    private static void createUser(String id, String ip, int port) {
        boolean canCreateUser = true;
        for (User user : Users) {
            if (user.getId().equals(id)) { // Check if the user ID matches the given ID
                canCreateUser = false; // User already exists
            }
        }
        if (canCreateUser) {
            User user = new User(id, ip, port);
            Users.add(user); // Add the new user to the list
        }
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
        deleteClientFile(peer.values[0]); // Clean up client file
        deletePortLine(peer); // Clean up port line
        peer.serverThread.closeServerSocket(); // Closes server socket
        Users.clear(); // peer will empty the list of users
        deleteMessageFile(peer);
    }

    /**
     * Deletes the client file associated with the given user ID.
     *
     * @param userId The ID of the user whose client file is to be deleted.
     */
    private static void deleteClientFile(String userId) {
        // Create a directory object for the "clients" directory
        File dir = new File("clients");

        // Check if the directory exists and is indeed a directory
        if (dir.exists() && dir.isDirectory()) {
            // Create a file object for the user's specific client file
            File userFile = new File(dir, userId);

            // If the user file exists, delete it
            if (userFile.exists()) {
                userFile.delete();
            }

            // Check if the directory is now empty, and if so, delete the directory
            if (dir.list().length == 0) {
                dir.delete();
            }
        }
    }

    /**
     * Deletes the Ports file if it exists.
     */
    private static void deletePortsFile() {
        // Create a file object for the Ports file
        File portsFile = new File("Ports");

        // Check if the Ports file exists
        if (portsFile.exists()) {
            // If it exists, delete the Ports file
            portsFile.delete();
        }
    }

    /**
     * Deletes a specific port line from the Ports file.
     *
     * @param peer The peer instance to get the global values.
     * @throws IOException If an I/O error occurs during file operations.
     */
    private static void deletePortLine(Peer peer) throws IOException {
        // Create a file object for the Ports file
        File portsFile = new File("Ports");

        // Use a BufferedReader to read the contents of the Ports file
        try (BufferedReader reader = new BufferedReader(new FileReader(portsFile))) {
            String line;
            StringBuilder contents = new StringBuilder();

            // Read each line from the Ports file
            while ((line = reader.readLine()) != null) {
                // Skip the line that matches the value to be deleted
                if (line.equals(peer.values[1])) {
                    continue;
                }
                // Append the line to the StringBuilder for the contents
                contents.append(line).append(System.lineSeparator());
            }
            // Close the reader
            reader.close();

            // Write the modified contents back to the Ports file
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(portsFile))) {
                writer.write(contents.toString());
                writer.close();
            }
        }

        // Check if the Ports file is now empty
        try (BufferedReader reader = new BufferedReader(new FileReader(portsFile))) {
            // If it is empty, delete the Ports file
            if (reader.readLine() == null) {
                reader.close();
                deletePortsFile();
            }
        }
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
                        Boolean clientIsOnline = false;

                        // Define the "clients" folder where online clients are registered
                        File clientsFolder = new File("clients");

                        // Check if the "clients" directory exists and is a directory
                        if (clientsFolder.exists() && clientsFolder.isDirectory()) {
                            // Get the list of files inside the "clients" directory
                            File[] clientsFiles = clientsFolder.listFiles();

                            // If the directory contains files (non-null), process them
                            if (clientsFiles != null) {
                                // Loop through each file in the "clients" directory
                                for (File clientFile : clientsFiles) {
                                    // Ensure that the current item is a file and not a subdirectory
                                    if (clientFile.isFile()) {
                                        // Check if the filename matches the other user's name
                                        if (clientFile.getName().equals(otherUser)) {
                                            clientIsOnline = true; // Set the flag if the other user is online
                                        }
                                        break; // Exit the loop once the client is found
                                    }
                                }
                            }
                        }

                        // If the other user (client) is not online, delete the message file
                        if (!clientIsOnline) {
                            chatsFile.delete(); // Delete the chat file for the offline user
                        }
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
            try {
                // Clean up the client file associated with the current user
                deleteClientFile(peer.values[0]);
                // Clean up the port line associated with the current client
                deletePortLine(peer); // Passes the current client's port
                peer.sslSocket.close();
            } catch (IOException e) {
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
     * Updates the list of active peers by reading ports and matching them with
     * client files.
     */
    public static void updateActivePeers() {
        File portsFile = new File("Ports"); // File containing the list of ports
        try (BufferedReader br = new BufferedReader(new FileReader(portsFile))) {
            String line;
            // Read each line (port) from the ports file
            while ((line = br.readLine()) != null) {
                int port = Integer.parseInt(line); // Parse the port number

                File folder = new File("clients"); // Directory containing client files
                String user = null;
                String ip = null;
                // Check if the directory exists
                if (folder.exists() && folder.isDirectory()) {
                    File[] files = folder.listFiles(); // Iterate through the files in the directory
                    if (files != null) {
                        for (File file : files) {
                            if (file.isFile()) { // Check if the current item is a file
                                try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                                    String filePort = reader.readLine(); // Read the port from the client file
                                    // If the port matches, get the username from the file name
                                    if (Integer.parseInt(filePort) == port) {
                                        user = file.getName(); // Retrieve the user ID from the file name
                                    }
                                    ip = reader.readLine(); // Read the port from the client file
                                } catch (IOException e) {
                                }
                            }
                        }
                    }
                }
                // Create or update the user based on the retrieved username and port
                createUser(user, ip, port);
            }
        } catch (IOException e) {
        }
    }

    /**
     * Verifies the input values for a user ID and port.
     * 
     * @param peer The peer instance to get the global values.
     * @return true if the values are valid; false otherwise.
     */
    private static boolean fileAndPortVerification(Peer peer) {
        // Check if the correct number of values was provided
        boolean returnValue = true;
        if (peer.values.length != 3) {
            returnValue = false;
        }

        File filename = new File("clients/" + peer.values[0]); // Check if the ID already exists
        if (filename.exists()) {
            setRepeatedId(peer, true);
        }

        // Check if the second value (port) is a valid number
        try {
            int port = Integer.parseInt(peer.values[1]);
            // Ensure the port number is within the valid range
            if (port <= 0 || port > 65535) {
                returnValue = false;
            }
        } catch (NumberFormatException e) {
            returnValue = false;
        }

        // Validate the IP address
        String ip = peer.values[2];
        if (!isValidIP(ip)) {
            returnValue = false;
        }

        // Check if the port is already in use
        File folder = new File("clients"); // Directory containing client files
        if (folder.exists() && folder.isDirectory()) {
            File[] files = folder.listFiles(); // Iterate through the files in the directory
            if (files != null) {
                for (File file : files) {
                    if (file.isFile()) { // Check if the current item is a file
                        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                            String filePort = reader.readLine(); // Read the port from the client file
                            // Check if the port already exists
                            if (filePort.equals(peer.values[1])) {
                                setRepeatedPort(peer, true);
                                returnValue = false;
                            }
                        } catch (IOException e) {
                        }
                    }
                }
            }
        }

        // If no errors were found, return true; otherwise, notify the user of the
        // conflict
        return returnValue;
    }

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
     * Finds a user by their ID from the list of active users.
     * 
     * @param id The ID of the user to find.
     * @return The User object if found; null otherwise.
     */
    private static User findReceiver(String id) {
        // Iterate through the list of active users
        for (User user : Users) {
            try {
                // Check if the ID matches and it is not the current user
                if (user.getId().equals(id) && !user.getId().equals(Users.get(0).getId())) {
                    return user; // Return the found user
                }
            } catch (NullPointerException e) {
                return null; // Return null if an error occurs
            }
        }
        return null; // Return null if no matching user is found
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
