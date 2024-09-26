package com.p2pmessagingapp;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.HashSet;
import java.util.Set;

public class ServerThread extends Thread {

    private ServerSocket serverSocket;
    private Set<ServerThreadThread> serverThreadThreads = new HashSet<ServerThreadThread>();

    public ServerThread(String portNum) throws IOException {
        serverSocket = new ServerSocket(Integer.valueOf(portNum));        
    }

    public void run() {
        try {

           while(true) {  // Infinite loop to keep the server running and accepting client connections.
            ServerThreadThread serverThreadThread = new ServerThreadThread(serverSocket.accept(), this);
            // Accepts a new client connection and creates a thread to manage it

            serverThreadThreads.add(serverThreadThread); 
            // Registers the new thread in the active threads collection

            serverThreadThread.start(); 
            // Initiates the new thread to handle communication with the connected client
}
        } catch (Exception e) { e.printStackTrace(); }
    }

    void sendMessage(String message) {
        try {
            // Sends the message to all connected clients through their active threads
            serverThreadThreads.forEach(t-> t.getPrintWriter().println(message));
        } catch (Exception e) { e.printStackTrace(); }
    }

    public Set<ServerThreadThread> getServerThreadThreads() { return serverThreadThreads; }
}
