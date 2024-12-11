package com.p2pmessagingapp;

import java.io.Serializable;

import java.util.ArrayList;
import java.util.List;

import java.security.cert.X509Certificate;

/**
 * The User class represents a peer in the P2P messaging system.
 * Each user has a unique ID, IP, port, and a certificate.
 * This class implements Serializable so that User objects can be sent over the
 * network.
 */
public class User implements Serializable {
    private static final long serialVersionUID = 1L; // Serialization ID for versioning

    private final String id; // Unique identifier for the user
    private final String ip; // Internet protocol for the user
    private final int port; // Port number associated with the user
    private final String receiverId; // Identifier of the user that this user wants to find (possibly null)
    private final X509Certificate certificate; // Certificate associated with the user
    private List<String> interests = new ArrayList<>(); // List of interests of this user
    private final String groupName; // Name of the group that this user is going to send a message in (this field
                                    // only serves to the server know what field to encrypt)

    /**
     * Constructs a User instance with a given ID, IP, port, receiverId, and
     * certificate.
     *
     * @param id          The unique ID of the user.
     * @param ip          The IP address of the user.
     * @param port        The port number the user is connected to.
     * @param receiverId  The ID of the user this user wants to communicate with.
     * @param certificate The X509Certificate of the user.
     * @param interests   The list of interests of the user.
     * @param groupName   The groupName of the user.
     */
    public User(String id, String ip, int port, String receiverId, X509Certificate certificate,
            List<String> interests, String groupName) {
        this.id = id;
        this.ip = ip;
        this.port = port;
        this.receiverId = receiverId;
        this.certificate = certificate;
        this.interests = interests;
        this.groupName = groupName;
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------GETTERS------------------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Gets the ID of the user.
     *
     * @return The ID of the user.
     */
    public String getId() {
        return id;
    }

    /**
     * Gets the Ip of the user.
     *
     * @return The Ip of the user.
     */
    public String getIp() {
        return ip;
    }

    /**
     * Gets the port of the user.
     *
     * @return The port of the user.
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

    /**
     * Gets the certificate of the user.
     *
     * @return The certificate of the user.
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Gets the interests of the user.
     *
     * @return The interests of the user.
     */
    public List<String> getInterests() {
        return interests;
    }

    /**
     * Sets the interests of the user.
     * 
     * @param interests New list of interests of this user
     *
     * @return The interests of the user.
     */
    public void setInterests(List<String> interests) {
        this.interests = interests;
    }

    /**
     * Gets the groupName of the user.
     *
     * @return The groupName of the user.
     */
    public String getGroupName() {
        return groupName;
    }
}
