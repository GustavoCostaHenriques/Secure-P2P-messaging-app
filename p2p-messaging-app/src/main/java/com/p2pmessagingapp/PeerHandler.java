package com.p2pmessagingapp;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;

import javax.net.ssl.SSLSocket;

/**
 * The PeerHandler class extends Thread to handle incoming messages from a
 * connected peer.
 * It reads messages over a secure SSL socket and processes them accordingly.
 */
public class PeerHandler extends Thread {
    private InputStream inputStream; // Input stream to read data from the socket
    private SSLSocket sslSocket; // SSL socket for secure communication with the peer
    private PeerServer peerServer; // PeerServer that created this peerHandler

    /**
     * Constructs a PeerHandler instance with the specified SSL socket.
     *
     * @param sslSocket The SSL socket connected to the peer.
     * @throws IOException If an error occurs while obtaining the input stream from
     *                     the socket.
     */
    public PeerHandler(SSLSocket sslSocket, PeerServer peerServer) throws IOException {
        this.sslSocket = sslSocket; // Initialize the SSL socket
        this.peerServer = peerServer; // Initialize the peerServer
    }

    /**
     * Constructs a PeerHandler instance.
     */
    public PeerHandler() {
    }

    /**
     * The main method that runs in the thread to listen for and process incoming
     * messages.
     * It continuously reads messages from the input stream and prints them to the
     * console.
     */
    @Override
    public void run() {
        try {
            this.inputStream = sslSocket.getInputStream(); // Get the input stream from the SSL socket
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream); // Create an ObjectInputStream for
                                                                                      // reading objects

            // Infinite loop to read incoming messages
            while (true) {
                // Block until an object is available to be read
                Message message = (Message) objectInputStream.readObject();
                if (message.getSender().getId().equals("SERVER")) {
                    if (message.getGroupKeys() != null)
                        peerServer.setGroupKeysToPeer(message.getGroupKeys());
                    else
                        peerServer.setUserSearched(message.getReceiver());
                } else {
                    peerServer.addMessageToPeer(message);
                }
                break; // Exit after reading the first message (consider removing this break for
                       // continuous listening)
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace(); // Log the error to see what went wrong
        }
    }
}
