package com.p2pmessagingapp;

import java.io.Serializable;
import java.sql.Time;
import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * The Message class represents a message being sent between users in the P2P
 * messaging system.
 * Each message contains a sender, a receiver, and the message content.
 * This class implements Serializable so that Message objects can be sent over
 * the network.
 */
public class Message implements Serializable {
    private static final long serialVersionUID = 1L; // Serialization ID for versioning

    private final User sender; // The user who is sending the message
    private final User receiver; // The user who is receiving the message
    private final String content; // The content of the message
    private final String fileName;
    private final String time;

    /**
     * Constructs a Message instance with a sender, receiver, and content.
     *
     * @param sender   The user sending the message.
     * @param receiver The user receiving the message.
     * @param content  The content of the message.
     */
    public Message(User sender, User receiver, String content, String fileName) {
        LocalDateTime timeStap = LocalDateTime.now();
        this.sender = sender; // Set the message sender
        this.receiver = receiver; // Set the message receiver
        this.content = content;
        this.fileName = fileName; // Set the message content
        this.time = timeStap.toString();
    }

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
     * Gets filename
     * @return filename
     */
    public String getFileName(){
        return fileName;
    }
    public String getTime(){
        return time;
    }
}
