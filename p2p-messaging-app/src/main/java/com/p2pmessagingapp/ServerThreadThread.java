package com.p2pmessagingapp;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ServerThreadThread extends Thread {

    private ServerThread serverThread;
    private Socket socket;
    private PrintWriter printWriter;

    public ServerThreadThread(Socket socket, ServerThread serverThread) {
        this.serverThread = serverThread;
        this.socket = socket;
    }

    public void run() {
        try {
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
            // Creates a BufferedReader to read incoming messages from the client socket.

          /**??? para que */  this.printWriter = new PrintWriter(socket.getOutputStream(), true);  /**??? */ 
            // Initializes a PrintWriter to send messages to the client, enabling auto-flush.

            while(true) 
            serverThread.sendMessage(bufferedReader.readLine());
            // Continuously reads messages from the client and send them to all connected clients.

        } catch (Exception e) {
            serverThread.getServerThreadThreads().remove(this);
        }
    }
    public PrintWriter getPrintWriter() { return printWriter; }
}
