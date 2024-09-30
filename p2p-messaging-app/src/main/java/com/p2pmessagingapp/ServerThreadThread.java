package com.p2pmessagingapp;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class ServerThreadThread extends Thread {

    private ServerThread serverThread;
    private SSLSocketFactory sslSocketFactory;
    private SSLSocket sslSocket;
    private PrintWriter printWriter;

    public ServerThreadThread(SSLSocket socket, ServerThread serverThread) {
        this.sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        this.serverThread = serverThread;
        this.sslSocket = socket;
    }

    public ServerThreadThread(Socket accept, ServerThread serverThread2) {
		//TODO Auto-generated constructor stub
	}

	public void run() {
        try {
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(this.sslSocket.getInputStream()));
            // Creates a BufferedReader to read incoming messages from the client socket.

          /**??? para que */  this.printWriter = new PrintWriter(sslSocket.getOutputStream(), true);  /**??? */ 
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