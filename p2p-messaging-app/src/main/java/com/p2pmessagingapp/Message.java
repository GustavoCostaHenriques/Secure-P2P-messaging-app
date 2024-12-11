package com.p2pmessagingapp;

import java.io.Serializable;
import java.security.Key;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

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
    private String time; // The time when the message was sent
    private Key groupKey; // key of the interest that the receiver is going to have
    private List<User> allUsers; // list of all the users that exist (this value only exist in a message where
                                 // the server is sending all the users to a certain peer so that the peer can
                                 // broadcast a message in a group chat)
    private final boolean broadcastMsg; // boolean to check if this message is a broadcast or not
    private final String fieldName; // Name of the field that the message (in case it is a broadcast message)

    /**
     * Constructs a Message instance with a sender, receiver, and content.
     *
     * @param sender   The user sending the message.
     * @param receiver The user receiving the message.
     * @param content  The content of the message.
     */
    public Message(User sender, User receiver, String content, boolean broadcastMsg, String fieldName) {
        LocalDateTime timeStap = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("ddMMyy-HH:mm:ss");
        this.sender = sender;
        this.receiver = receiver;
        this.content = content;
        this.broadcastMsg = broadcastMsg;
        this.fieldName = fieldName;
        this.time = timeStap.format(formatter);
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
     * Sets time
     * 
     */
    public void setTime(String time) {
        this.time = time;
    }

    /**
     * Gets group keys
     * 
     * @return groupKeys
     */
    public Key getGroupKey() {
        return groupKey;
    }

    /**
     * Sets the group keys to the argument given
     * 
     * @param groupKey group key to store
     */
    public void setGroupKeys(Key groupKey) {
        this.groupKey = groupKey;
    }

    /**
     * Gets the list of all the Users
     * 
     * @return allUsers
     */
    public List<User> getAllUsers() {
        return allUsers;
    }

    /**
     * Sets the list of all the users to the argument given
     * 
     * @param allUsers list of all the users to store
     */
    public void setAllUsers(List<User> allUsers) {
        this.allUsers = allUsers;
    }

    /**
     * Gets the boolean broadcastMsg of the message.
     *
     * @return The boolean broadcastMsg of the message.
     */
    public boolean getBroadcastMsg() {
        return broadcastMsg;
    }

    /**
     * Gets the fieldName of the message.
     *
     * @return The fieldName of the message.
     */
    public String getFieldName() {
        return fieldName;
    }

    public boolean equals(Message msg) {
        return (msg.getSender().getId().equals(this.sender.getId()))
                && (msg.getReceiver().getId().equals(this.receiver.getId()))
                && (msg.getContent().equals(this.content))
                && (msg.getTime().equals(this.time));
    }
}