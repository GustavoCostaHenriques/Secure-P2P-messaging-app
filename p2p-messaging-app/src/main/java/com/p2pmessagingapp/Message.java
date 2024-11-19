package com.p2pmessagingapp;

import java.io.Serializable;
import java.security.Key;
import java.time.LocalDateTime;
import java.util.Map;

/**
 * The Message class represents a message being sent between users in the P2P
 * messaging system.
 * Each message contains a sender, a receiver, the content of the message and
 * the file name where the message is going to be stored.
 * This class implements Serializable so that Message objects can be sent over
 * the network.
 */
public class Message implements Serializable {
    private static final long serialVersionUID = 1L; // Serialization ID for versioning

    private final User sender; // The user who is sending the message
    private final User receiver; // The user who is receiving the message
    private final String content; // The content of the message
    private final String time; // The time when the message was sent
    private Map<String, Key> groupKeys;

    /**
     * Constructs a Message instance with a sender, receiver, and content.
     *
     * @param sender   The user sending the message.
     * @param receiver The user receiving the message.
     * @param content  The content of the message.
     */
    public Message(User sender, User receiver, String content) {
        LocalDateTime timeStap = LocalDateTime.now();
        this.sender = sender;
        this.receiver = receiver;
        this.content = content;
        this.time = timeStap.toString();
    }

    // -----------------------------------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------GETTERS-AND-SETTERS------------------------------------------------------//
    // -----------------------------------------------------------------------------------------------------------------------------//

    /**
     * Gets the user who sent the message.
     *
     * @return The sender of the message.
     */
    public User getSender() {
        return sender;
    }

    /**
     * Gets the user who will receive the message.
     *
     * @return The receiver of the message.
     */
    public User getReceiver() {
        return receiver;
    }

    /**
     * Gets the content of the message.
     *
     * @return The content of the message.
     */
    public String getContent() {
        return content;
    }

    /**
     * Gets time
     * 
     * @return time
     */
    public String getTime() {
        return time;
    }

    /**
     * Gets group keys
     * 
     * @return groupKeys
     */
    public Map<String, Key> getGroupKeys() {
        return groupKeys;
    }

    /**
     * Sets the group keys to the argument given
     * 
     * @param groupKeys group keys to store
     */
    public void setGroupKeys(Map<String, Key> groupKeys) {
        this.groupKeys = groupKeys;
    }
}