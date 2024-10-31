package com.p2pmessagingapp;

import java.io.Serializable;

/**
 * The User class represents a peer in the P2P messaging system.
 * Each user has a unique ID and a port number they are connected to.
 * This class implements Serializable so that User objects can be sent over the
 * network.
 */
public class User implements Serializable {
    private static final long serialVersionUID = 1L; // Serialization ID for versioning

    private final String id; // Unique identifier for the user
    private final String ip; // Unique internet protocol for the user
    private final int port; // Port number associated with the user
    private final String receiverId; // Identifier of the user that this user wants to find (possibly null)

    /**
     * Constructs a User instance with a given ID and port.
     *
     * @param id   The unique ID of the user.
     * @param port The port number the user is connected to.
     */
    public User(String id, String ip, int port, String receiverId) {
        this.id = id; // Set the user's ID
        this.ip = ip; // Set the user's IP
        this.port = port; // Set the user's port
        this.receiverId = receiverId; // Set the user's receiverId
    }

    /**
     * Gets the ID of the user.
     *
     * @return The ID of the user.
     */
    public String getId() {
        return id;
    }

    /**
     * Gets the IP of the user.
     *
     * @return The IP of the user.
     */
    public String getIp() {
        return ip;
    }

    /**
     * Gets the port number the user is connected to.
     *
     * @return The port number.
     */
    public int getPort() {
        return port;
    }

    /**
     * Gets the receiverId of the user.
     *
     * @return The receiverId of the user.
     */
    public String getReceiverId() {
        return receiverId;
    }
}
