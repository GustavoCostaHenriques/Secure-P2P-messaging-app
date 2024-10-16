package com.p2pmessagingapp;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.util.Scanner;

import javax.net.ssl.SSLSocket;

/**
 * The PeerHandler class extends Thread to handle incoming messages from a
 * connected peer.
 * It reads messages over a secure SSL socket and processes them accordingly.
 */
public class PeerHandler extends Thread {
    private InputStream inputStream; // Input stream to read data from the socket
    private SSLSocket sslSocket; // SSL socket for secure communication with the peer

    /**
     * Constructs a PeerHandler instance with the specified SSL socket.
     *
     * @param sslSocket The SSL socket connected to the peer.
     * @throws IOException If an error occurs while obtaining the input stream from
     *                     the socket.
     */
    public PeerHandler(SSLSocket sslSocket) throws IOException {
        this.sslSocket = sslSocket; // Initialize the SSL socket
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
                writeOnChat(message.getTime()+"-"+"[" + message.getSender().getId() + "] " + message.getContent(), message.getFileName());
                System.out.println("[" + message.getSender().getId() + "] " + message.getContent());
                break; // Exit after reading the first message (consider removing this break for
                       // continuous listening)
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace(); // Log the error to see what went wrong
        }
    }
    private void writeOnChat(String message, String fileName){
        try {
            BufferedWriter fileWriter;
            try (Scanner sc = new Scanner(fileName)) {
                    fileWriter = new BufferedWriter(new FileWriter(fileName, true)); // append mode
                    while (sc.hasNextLine()) {
                        sc.nextLine();
                    }
                } // append
            fileWriter.write(message);
            fileWriter.write(System.getProperty("line.separator"));
            fileWriter.close();
        } catch (IOException e) {
            System.out.println("ERROR-NO SUCH FILE EXISTS");
        }
    }
}
