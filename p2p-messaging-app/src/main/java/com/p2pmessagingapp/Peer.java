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
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.Socket;

import javax.json.Json;

public class Peer {

    public static void main(String[] args) throws Exception {
        
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Enter your id & port");
        String[] values = bufferedReader.readLine().split(" "); // Reads and splits user input details
        
        ServerThread serverThread = new ServerThread(values[1]);
        serverThread.start();
        new Peer().updateListenToPeers(bufferedReader,values[0], serverThread);
    }

    public void updateListenToPeers(BufferedReader bufferedReader, String id, ServerThread serverThread) throws Exception {
        System.out.println("Enter hostname:port");
        System.out.println(" peers to receive messages from(s to skip):");
        String input = bufferedReader.readLine();
        String[] inputValues = input.split(" ");
        if(!input.equals("s")) {
            for (int i = 0; i < inputValues.length; i++) {
                String[] address = inputValues[i].split(":");
                Socket socket = null;
                try {
                    socket = new Socket(address[0], Integer.valueOf(address[1]));
                    new PeerThread(socket).start();
        
                } catch (Exception e) {
                    if (socket != null) socket.close();
                    else System.out.println("invalid input");
                }
            }
        }
        communicate(bufferedReader, id, serverThread);
    }

    public void communicate(BufferedReader bufferedReader, String id, ServerThread serverThread) {
        try {
            System.out.println("You can now communicate (e to exit, c to change)");
            boolean flag = true;
            while(flag) {
                String message = bufferedReader.readLine();
                if(message.equals("e")) {
                    flag = false;
                    break;
                } else if (message.equals("c")) {
                    updateListenToPeers(bufferedReader, id, serverThread);
                } else {
                    StringWriter stringWriter = new StringWriter();
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
}
