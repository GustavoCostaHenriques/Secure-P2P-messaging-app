package com.p2pmessagingapp;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.net.SocketException;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

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
    private String contentFromServer = null; // content of the message that is going to be sent from the user
    private User userSearched = null; // user that this peer is trying to find

    /**
     * Constructs a PeerServer instance that creates an SSL server socket on the
     * specified port.
     *
     * @param portNum The port number on which the server will listen for incoming
     *                connections.
     * @throws IOException If an error occurs while creating the server socket.
     */
    public PeerServer(int portNum) throws IOException {
        createSSLServerSocket(portNum); // Initialize the server socket
    }

    /**
     * Creates an SSLServerSocket that listens on the specified port using TLS
     * protocol.
     *
     * @param port The port number on which the server socket will listen.
     */
    public void createSSLServerSocket(int port) {
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.2"); // Create SSL context for TLS 1.2
            KeyManagerFactory keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keys = KeyStore.getInstance("JKS");

            // Load the keystore containing the server's private key
            try (InputStream stream = new FileInputStream("stream.jks")) {
                keys.load(stream, "p2pmessagingapp".toCharArray());
            }
            keyManager.init(keys, "p2pmessagingapp".toCharArray()); // Initialize the key manager with the keys

            // Load the truststore containing trusted certificates
            KeyStore store = KeyStore.getInstance("JKS");
            try (InputStream storeStream = new FileInputStream("storestream.jks")) {
                store.load(storeStream, "p2pmessagingapp".toCharArray());
            }

            TrustManagerFactory trustManager = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManager.init(store); // Initialize the trust manager with the truststore

            context.init(keyManager.getKeyManagers(), trustManager.getTrustManagers(), null); // Initialize the SSL
                                                                                              // context
            SSLServerSocketFactory factory = context.getServerSocketFactory(); // Create the server socket factory
            serverSocket = (SSLServerSocket) factory.createServerSocket(port); // Create the SSLServerSocket
            serverCreated = true;

        } catch (IOException e) {
            serverCreated = false;
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException | CertificateException
                | KeyManagementException e) {
            e.printStackTrace(); // Outras exceções de SSL e de I/O
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
     * Sends a Message to the specified peer by serializing it and using the Peer
     * instance.
     *
     * @param message The Message to be sent to the peer.
     * @throws Exception If an error occurs during the sending process.
     */
    public void sendMessage(Message message) throws Exception {
        peer = new Peer(message.getReceiver().getId(), message.getReceiver().getIp(),
                message.getReceiver().getPort()); // Create a Peer instance for the receiver
        byte[] serializedMessage = serializeMessage(message); // Serialize the message
        peer.sendMessage(serializedMessage); // Send the serialized message to the peer
    }

    /**
     * Closes the server socket.
     * 
     * @throws IOException If an error occurs during the closing process.
     */
    public void closeServerSocket() throws IOException {
        if (serverSocket != null) { // Checks if server is null
            serverSocket.close();
        }
    }

    /**
     * Gets the serverCreated variable of the server.
     *
     * @return The serverCreated variable of the server.
     */
    public boolean getServerCreated() {
        return serverCreated;
    }

    /**
     * Gets the content of the message sent from the server.
     *
     * @return The content of the message sent from the server.
     */
    public String getContentFromTheServer() {
        return contentFromServer;
    }

    /**
     * Sets the content from the server to the content value.
     *
     * @param content The content that is going to replace the value of the
     *                contentFromServer.
     */
    public void setContentFromTheServer(String content) {
        System.out.println("Entrou aqui e vai meter no servidor " + this.serverSocket.getLocalPort() + " content como: "
                + content);
        this.contentFromServer = content;
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
        if (user != null) {
            System.out
                    .println("Entrou aqui e vai meter no servidor " + this.serverSocket.getLocalPort() + " user como: "
                            + user.getId());
        } else {
            System.out.println(
                    "Entrou aqui e vai meter no servidor " + this.serverSocket.getLocalPort() + " user como null");
        }
        this.userSearched = user;
    }
}
