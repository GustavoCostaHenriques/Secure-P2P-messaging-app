package com.p2pmessagingapp;

import java.io.ByteArrayInputStream;
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
        System.out.println("Estou à espera na porta: "+sslSocket.getLocalPort());
        while(true) {
            try {
                this.inputStream = sslSocket.getInputStream();
                // Verifique se há bytes disponíveis para ler
                if (inputStream.available() > 0) {
                    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(inputStream.readAllBytes());
                    Message message;
                    // Recuperar o objeto Message
                    try (ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream)) {
                        // Recuperar o objeto Message
                        message = (Message) objectInputStream.readObject();
                    }
    
                    // Acessar os detalhes da mensagem e imprimi-los
                    System.out.println("[" + message.getSender().getId() + "] " + message.getContent());
                }
            } catch (IOException | ClassNotFoundException e) {} 
        }
    }
}
