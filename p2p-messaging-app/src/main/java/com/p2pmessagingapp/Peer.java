/***
 * IMPORTANTE: 
 *  A lógica que o vídeo usou está um bocado diferente do que nós queremos em alguns aspetos. Por exemplo,
 *  nós não queremos que os users dêm permissão para outros users poderem mandar mensagem. O que temos que 
 *  fazer é com que todos os users tenham permissão para falar com todos os outros. E outra coisa é que neste
 *  momento é possível uma mensagem enviada por um user ir para vários outros user e não um só, também temos de 
 *  mudar isso.
 */



package com.p2pmessagingapp;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.Socket;

import javax.json.Json;

public class Peer {
    
    public static void main(String[] args) throws Exception {

        String[] values;
        ServerThread serverThread;
        String errorMessage;
        
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("=> Please enter your id & port below:");
                
        while (true) { 
            values = bufferedReader.readLine().split(" "); // Reads and splits user input details

            errorMessage = "";
            File filename = new File("clients/" + values[0]);
            if(filename.exists()) errorMessage = "ID";  

            File folder = new File("clients");
            if(folder.exists() && folder.isDirectory()) {
                File[] files = folder.listFiles();
                if (files != null) {
                    for (File file : files) {
                        if (file.isFile()) {
                            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                                String filePort = reader.readLine(); // Reads the file content
                                if (filePort.equals(values[1])) {
                                    if(errorMessage.equals("")) errorMessage = "Port";
                                    else errorMessage = "ID and Port";
                                }
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            }
        
            if(errorMessage.equals("")) break;

            System.out.println("=> " + errorMessage + " already in use, please insert a different " + errorMessage + ":");

        }
        serverThread = new ServerThread(values[1]);
        serverThread.start();
        createClientFile(values[0], values[1]);

        new Peer().updateListenToPeers(bufferedReader,values[0], serverThread);
    }
       
    
    
    public void updateListenToPeers(BufferedReader bufferedReader, String id, ServerThread serverThread) throws Exception {

        System.out.println("Enter hostname:port");
        System.out.println(" peers to receive messages from(s to skip):");

        String input = bufferedReader.readLine();
        String[] inputValues = input.split(" "); // Split input by spaces into host:port pairs
        
        if(!input.equals("s")) {

            for (int i = 0; i < inputValues.length; i++) {
                String[] address = inputValues[i].split(":");
                Socket socket = null;

                try {  // Create a socket and start a PeerThread for communication
                    socket = new Socket(address[0], Integer.valueOf(address[1]));
                    new PeerThread(socket).start(); // Initiates a PeerThread for communication with the connected peer

                } catch (Exception e) { // Close the socket if it exists; print "invalid input" if not.
                    if (socket != null) socket.close();
                    else System.out.println("invalid input");
                }
            }
        }
        // Handles user communication with connected peers.
        communicate(bufferedReader, id, serverThread);
    }
    


    /**
    * Facilitates communication with peers by reading user input and sending messages.
    *
    * @param bufferedReader The BufferedReader to read user input from the console.
    * @param id The unique identifier of the user (peer).
    * @param serverThread The ServerThread instance responsible for sending messages to peers.
    */

    public void communicate(BufferedReader bufferedReader, String id, ServerThread serverThread) {

        try {

            System.out.println("You can now communicate (e to exit, c to change)");
            boolean flag = true;
            while(flag) {

                String message = bufferedReader.readLine();

                if(message.equals("e")) { //exit the communication
                    flag = false;
                    break;

                } else if (message.equals("c")) { //change the peer
                    updateListenToPeers(bufferedReader, id, serverThread);
                    
                } else {
                    StringWriter stringWriter = new StringWriter();
                    
                    // Creates a JSON object with the user's ID and message for transmission.
                    Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                                                .add("id", id)
                                                .add("message", message)
                                                .build());
                    serverThread.sendMessage(stringWriter.toString());
                }
            }
            System.exit(0);
        } catch (Exception e) { e.printStackTrace(); }
    }

    public static void createClientFile(String id, String port) {
        try {
            File dir = new File("clients");
            if (!dir.exists()) {
                dir.mkdir(); // Criar a diretoria se não existir
            }

            File file = new File(dir, id);
            BufferedWriter writer = new BufferedWriter(new FileWriter(file));
            writer.write(port); // Escrever a porta no ficheiro
            writer.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

