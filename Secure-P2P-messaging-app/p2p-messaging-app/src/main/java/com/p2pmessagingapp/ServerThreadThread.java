package com.p2pmessagingapp;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ServerThreadThread extends Thread {

    private ServerThread serverThread;
    private Socket socket; // Changed from SSLSocket to Socket
    private PrintWriter printWriter;

    public ServerThreadThread(Socket socket, ServerThread serverThread) {
        this.socket = socket; // Initialize with a regular Socket
        this.serverThread = serverThread;
    }

    public void run() {
        try {
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
            // Creates a BufferedReader to read incoming messages from the client socket.

            this.printWriter = new PrintWriter(socket.getOutputStream(), true);  
            // Initializes a PrintWriter to send messages to the client, enabling auto-flush.

            while (true) {
                String message = bufferedReader.readLine();
                if (message != null) {
                    serverThread.sendMessage(message);
                }
            }
            // Continuously reads messages from the client and sends them to all connected clients.

        } catch (Exception e) {
            serverThread.getServerThreadThreads().remove(this);
            // Handle any exceptions, removing this thread from the server's active thread list
        }
    }

    public PrintWriter getPrintWriter() {
        return printWriter;
    }
}
