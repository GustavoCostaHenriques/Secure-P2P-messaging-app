package com.p2pmessagingapp;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;

import java.net.SocketException;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * The PeerServer class extends Thread to create a secure server socket
 * that listens for incoming peer connections and handles message exchanges.
 */
public final class PeerServer extends Thread {

    private SSLServerSocket serverSocket; // SSLServerSocket to accept secure connections
    private Peer peer; // Peer instance to handle communication with a connected peer
    private PeerHandler peerHandler;
    private boolean serverCreated = false;
    private User userSearched = null; // user that this peer is trying to find
    private List<User> allUsers = null; // all the users that exist
    private String groupNameEncrypted = null; // the encrypted group name that this peer wants to send a message in

    /**
     * Constructs a PeerServer instance that creates an SSL server socket on the
     * specified port.
     *
     * @param portNum The port number on which the server will listen for incoming
     *                connections.
     * @throws IOException If an error occurs while creating the server socket.
     */
    public PeerServer(int port, String keyStoreFile, String trustStoreFile, String password, Peer peer) {
        this.peer = peer;
        createSSLServerSocket(port, keyStoreFile, trustStoreFile, password);
    }

    /**
     * The main method that runs in the thread to accept client connections and
     * handle them.
     * It continuously listens for incoming connections and starts a PeerHandler for
     * each connection.
     */
    @Override
    public void run() {
        try {
            while (!serverSocket.isClosed()) { // Infinite loop to keep the server running and accepting client
                                               // connections.
                SSLSocket sslSocket = (SSLSocket) serverSocket.accept(); // Accept the connection and return a
                                                                         // Socket
                peerHandler = new PeerHandler(sslSocket, this); // Create a new PeerHandler for the connection
                peerHandler.start(); // Start the PeerHandler thread
            }
        } catch (SocketException e) {
            if (!serverSocket.isClosed())
                e.printStackTrace(); // Log the error if it's not due to the socket being closed
        } catch (IOException e) {
            e.printStackTrace(); // Log any other IOExceptions that occur
        }
    }

    /**
     * Creates an SSLServerSocket that listens on the specified port using TLS
     * protocol.
     *
     * @param port The port number on which the server socket will listen.
     */
    public void createSSLServerSocket(int port, String keyStoreFile, String trustStoreFile, String password) {
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.2");

            // Load the KeyStore containing the peer's private key and certificate
            KeyManagerFactory keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (InputStream keyStream = new FileInputStream(keyStoreFile)) {
                keyStore.load(keyStream, password.toCharArray());
            }
            keyManager.init(keyStore, password.toCharArray());

            // Load the TrustStore containing trusted certificates
            TrustManagerFactory trustManager = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream trustStream = new FileInputStream(trustStoreFile)) {
                trustStore.load(trustStream, password.toCharArray());
            }
            trustManager.init(trustStore);

            // Initialize SSL context with KeyManager and TrustManager
            context.init(keyManager.getKeyManagers(), trustManager.getTrustManagers(), null);

            // Create the SSL server socket
            SSLServerSocketFactory factory = context.getServerSocketFactory();
            serverSocket = (SSLServerSocket) factory.createServerSocket(port);
            serverCreated = true;

        } catch (IOException e) {
            serverCreated = false;
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException
                | CertificateException | KeyManagementException e) {
            serverCreated = false;
            e.printStackTrace();
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
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        // Serialize the Message object into a byte array
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {
            objectOutputStream.writeObject(message); // Serializes object Message
        }

        return byteArrayOutputStream.toByteArray(); // Return the byte array
    }

    /**
     * Sends a Message to the specified peer by serializing it and using the Peer
     * instance.
     *
     * @param message The Message to be sent to the peer.
     * @throws Exception If an error occurs during the sending process.
     */
    public void sendMessage(Message message) throws Exception {
        Peer peerInstance = new Peer(message.getReceiver().getId(), message.getReceiver().getIp(),
                message.getReceiver().getPort(), message.getReceiver().getInterests(), message.getSender()); // Create a
                                                                                                             // Peer
                                                                                                             // instance
                                                                                                             // for the
                                                                                                             // receiver
        byte[] serializedMessage = serializeMessage(message); // Serialize the message
        peerInstance.sendMessage(serializedMessage); // Send the serialized message to the peer
    }

    public void addMessageToPeer(Message message) {
        peer.addMessageToHistory(message);
    }

    public void addMessageGroupToPeer(Message message) {
        peer.addMessageGroupToHistory(message);
    }

    public void setGroupKeyToPeer(Key groupKey) {
        peer.setGroupKey(peer, groupKey);
    }

    public void uploadCloudPeer(String objectKey, String content) {
        peer.sendMessageToCloud(objectKey, content);
    }

    /**
     * Closes the server socket.
     * 
     * @throws IOException If an error occurs during the closing process.
     */
    public void closeServerSocket() throws IOException {
        if (serverSocket != null) // Checks if server is null
            serverSocket.close();
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------GETTERS-AND-SETTERS------------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Gets the serverCreated variable of the server.
     *
     * @return The serverCreated variable of the server.
     */
    public boolean getServerCreated() {
        return serverCreated;
    }

    /**
     * Gets the user sent from the server.
     *
     * @return The user sent from the server.
     */
    public User getUserSearched() {
        return userSearched;
    }

    /**
     * Sets the userSearched to the user value.
     * 
     * @param user The user that is going to replace the value of the userSearched.
     */
    public void setUserSearched(User user) {
        this.userSearched = user;
    }

    /**
     * Gets the list of all the users sent from the server.
     *
     * @return The list of all the users sent from the server.
     */
    public List<User> getAllUsers() {
        return allUsers;
    }

    /**
     * Sets the list of all the users to the list users.
     * 
     * @param user The list pf alll the users that is going to replace the value of
     *             allUsers.
     */
    public void setAllUsers(List<User> users) {
        this.allUsers = users;
    }

    /**
     * Gets the groupNameEncrypted from the server.
     *
     * @return The groupNameEncrypted sent from the server.
     */
    public String getGroupNameEncrypted() {
        return groupNameEncrypted;
    }

    /**
     * Sets the groupNameEncrypted to the string groupNameEncrypted.
     * 
     * @param groupNameEncrypted The groupNameEncrypted string that is going to be
     *                           store in the variable groupNameEncrypted.
     */
    public void setGroupNameEncrypted(String NameEncrypted) {
        this.groupNameEncrypted = NameEncrypted;
    }

    /**
     * Gets the group key of this peer.
     *
     * @return The group key of this peer.
     */
    public Key getPeerKey() {
        return peer.getGroupKey();
    }
}
