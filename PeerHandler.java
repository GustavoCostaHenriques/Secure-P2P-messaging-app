package com.p2pmessagingapp;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;

import javax.net.ssl.SSLSocket;

public class PeerHandler extends Thread {
    private InputStream inputStream; 
    private final SSLSocket sslSocket; 

    public PeerHandler(SSLSocket sslSocket) throws IOException{
        this.sslSocket = sslSocket;
    }

    @Override
    public void run() {
        try {
            this.inputStream = sslSocket.getInputStream();
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);

            // Loop infinito para ler as mensagens recebidas
            while (true) {
                // Bloqueia até que um objeto esteja disponível para ser lido
                Message message = (Message) objectInputStream.readObject();

                // Acessar os detalhes da mensagem e imprimi-los
                System.out.println("[" + message.getSender().getId() + "] " + message.getContent());
                break;
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();  // Log de erro para ver o que pode ter acontecido
        }
    }
}
