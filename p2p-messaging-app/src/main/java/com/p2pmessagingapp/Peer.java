package com.p2pmessagingapp;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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
 * communication
 * between users.
 */
public class Peer {

    private SSLSocket sslSocket; // SSL socket for secure communication
    private String[] values; // Array to hold user input values (ID and port)
    private PeerServer serverThread; // Thread for the peer server
    private BufferedReader bufferedReader; // Buffered reader for user input
    private final static List<User> Users = new ArrayList<>(); // Creates a list of users

    /**
     * The main method serves as the entry point for the P2P messaging application.
     * It prompts the user for their ID and port, verifies the input, starts the
     * peer server, and facilitates communication with other peers.
     *
     * @param args Command line arguments (not used in this application).
     * @throws Exception If an error occurs during initialization or communication.
     */
    public static void main(String[] args) throws Exception {
        Peer peer = new Peer();
        // Add a shutdown hook to delete client and port files/directories upon exiting
        addShutdownHook(peer); // Triggered by pressing 'Control + C'

        System.out.println("=> Please enter your id & port below:");
        // Continuously prompt the user for ID and port until valid input is received
        while (true) {
            peer.bufferedReader = new BufferedReader(new InputStreamReader(System.in));
            // Read and split user input details into the values array
            peer.values = peer.bufferedReader.readLine().split(" ");
            boolean verificationStatus = fileAndPortVerification(peer); // Verify input values
            if (verificationStatus) {
                break; // Exit the loop if verification is successful
            }
        }

        // Start the peer server on the specified port
        peer.serverThread = new PeerServer(Integer.parseInt(peer.values[1]));
        peer.serverThread.start();

        // Create user attributes (e.g., user file and socket) based on user input
        createUserAtributtes(peer, peer.values[0], Integer.parseInt(peer.values[1]));

        // Prompt the user for a peer to communicate with
        askForcommunication(peer, peer.bufferedReader, peer.values[0], peer.serverThread);
        // Keep the program running indefinitely
        keepProgramRunning();
    }

    /**
     * Constructs a Peer instance and initializes user attributes.
     *
     * @param address The ID of the user.
     * @param port    The port number to be used for communication.
     * @throws Exception If an error occurs during initialization.
     */
    public Peer(String address, int port) throws Exception {
        createUserAtributtes(this, address, port); // Create user attributes for a new peer
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
                deleteClientFile(peer.values[0]); // Clean up client file
                deletePortLine(peer); // Clean up port line
                Peer.main(peer.values);
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
        try {
            // Inform the user that communication can now begin
            System.out.println("=>You can now communicate ('%% exit' to exit, '%% change' to change)");

            OUTER: while (true) {
                // Read user input for the message
                String content = bufferedReader.readLine();
                switch (content) {
                    case "%% exit":
                        // Exit the communication
                        deleteClientFile(peer.values[0]); // Clean up client file
                        deletePortLine(peer); // Clean up port line
                        break OUTER; // Break out of the loop
                    case "%% change":
                        // Change the peer for communication
                        askForcommunication(peer, bufferedReader, id, serverThread); // Prompt for a new peer
                        break;
                    default:
                        // Create a message and send it to the receiver
                        Message message = new Message(Users.get(0), receiver, content);
                        serverThread.sendMessage(message); // Send the message through the server thread
                        break;
                }
            }
            Peer.main(peer.values); // Return to the main peer interface
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
     * @param peer    The peer instance to get the global values.
     * @param address The address of the user.
     * @param port    The port number associated with the user.
     */
    private static void createUserAtributtes(Peer peer, String address, int port) {
        createPortsFile(port);
        createSSLSocket(peer, "localhost", port);
        createClientFile(address, port);
        createUser(address, port);
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
     * Creates an SSL socket for secure communication with the specified address and
     * port.
     *
     * @param peer    The peer instance to get the global values.
     * @param address The address to connect to.
     * @param port    The port number to connect to.
     */
    private static void createSSLSocket(Peer peer, String address, int port) {
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
            peer.sslSocket = (SSLSocket) factory.createSocket(address, port);

        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException
                | CertificateException | KeyManagementException e) {
        }
    }

    /**
     * Creates a client file for the user with the specified ID and writes the port
     * number to it.
     *
     * @param id   The identifier of the user.
     * @param port The port number to be written in the client file.
     */
    private static void createClientFile(String id, int port) {
        try {
            File dir = new File("clients");
            if (!dir.exists()) {
                dir.mkdir(); // Create the directory if it does not exist
            }

            File file = new File(dir, id);
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                writer.write(String.valueOf(port)); // write the port in the file
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
     * @param port The port number associated with the user.
     */
    private static void createUser(String id, int port) {
        boolean canCreateUser = true;
        for (User user : Users) {
            if (user.getId().equals(id)) { // Check if the user ID matches the given ID
                canCreateUser = false; // User already exists
            }
        }
        if (canCreateUser) {
            User user = new User(id, port);
            Users.add(user); // Add the new user to the list
        }
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ---------------------------------------------------CLIENT-AND-PORT-REMOVAL---------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

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
            System.out.println("Shutdown hook triggered."); // Notify that the shutdown hook is activated
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
        try {
            // Sleep for a long time, keeping the program active
            Thread.sleep(Long.MAX_VALUE);
        } catch (InterruptedException e) {
            // Handle the interruption and restore the interrupted status
            Thread.currentThread().interrupt();
            System.out.println("Program interrupted."); // Notify that the program was interrupted
            // Exit the program with status code 0
            System.exit(0);
        }
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
                                } catch (IOException e) {
                                }
                            }
                        }
                    }
                }
                // Create or update the user based on the retrieved username and port
                createUser(user, port);
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
        if (peer.values.length != 2) {
            System.out.println("=> error: input must be in the format 'id port' (e.g., Valeta 6969).");
            return false;
        }

        String errorMessage = "";
        File filename = new File("clients/" + peer.values[0]); // Check if the ID already exists
        if (filename.exists())
            errorMessage = "ID"; // Set error message if ID already exists

        // Check if the second value (port) is a valid number
        try {
            int port = Integer.parseInt(peer.values[1]);
            // Ensure the port number is within the valid range
            if (port <= 0 || port > 65535) {
                System.out.println("=> error: port must be a number between 1 and 65535.");
                return false;
            }
        } catch (NumberFormatException e) {
            System.out.println("=> error: port must be a valid number.");
            return false;
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
                                // Build appropriate error message based on conflicts
                                if (errorMessage.equals(""))
                                    errorMessage = "Port";
                                else
                                    errorMessage = "ID and Port";
                            }
                        } catch (IOException e) {
                        }
                    }
                }
            }
        }

        // If no errors were found, return true; otherwise, notify the user of the
        // conflict
        if (errorMessage.equals(""))
            return true;

        System.out.println("=> " + errorMessage + " already in use, please insert a different " + errorMessage + ":");
        return false;
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

}
