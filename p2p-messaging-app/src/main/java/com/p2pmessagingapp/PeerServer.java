package com.p2pmessagingapp;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public final class PeerServer extends Thread {

    private static SSLServerSocket serverSocket; // Changed from SSLServerSocket to ServerSocket
    private Peer peer;
    private static String userId;

    public PeerServer(String userId, int portNum) throws IOException {
        PeerServer.userId = userId;
        createSSLServerSocket(portNum);
    }

    public void createSSLServerSocket(int port) throws IOException {
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.2");
            KeyManagerFactory keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keys = KeyStore.getInstance("JKS");
            try (InputStream stream = new FileInputStream("stream.jks")){
                keys.load(stream, "p2pmessagingapp".toCharArray());
            }
            keyManager.init(keys, "p2pmessagingapp".toCharArray());

            KeyStore store = KeyStore.getInstance("JKS");
            try(InputStream storeStream = new FileInputStream("storestream.jks")) {
                store.load(storeStream, "p2pmessagingapp".toCharArray());
            }

            TrustManagerFactory trustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManager.init(store);

            context.init(keyManager.getKeyManagers(), trustManager.getTrustManagers(), null);
            SSLServerSocketFactory factory = context.getServerSocketFactory();
            serverSocket = (SSLServerSocket) factory.createServerSocket(port);

            
        } catch (NoSuchAlgorithmException | KeyStoreException | 
                UnrecoverableKeyException | CertificateException | KeyManagementException e) {}
        

    }

    @Override
    public void run() {
        try {
            while (true) {  // Infinite loop to keep the server running and accepting client connections.
                SSLSocket sslsocket = (SSLSocket) serverSocket.accept();  // Accept the connection and return a Socket
                PeerHandler peerHandler = new PeerHandler(sslsocket);
                peerHandler.start();
            }
        } catch (IOException e) {}
    }

    private static byte[] serializeMessage(Message message) throws IOException{
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {
            objectOutputStream.writeObject(message); // Serializes object Message
        }
        
        return byteArrayOutputStream.toByteArray();
    }

    public void sendMessage(Message message) throws Exception {

        peer = new Peer(message.getReceiver().getId(), message.getReceiver().getPort());
        System.out.println("Porta do bacano: "+ message.getReceiver().getPort());
        byte[] serializedMessage = serializeMessage(message);
        peer.sendMessage(serializedMessage);
        /* try {
            //desirialize
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(serializedMessage);
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            
            // Recuperar o objeto Message
            Message message = (Message) objectInputStream.readObject();
            objectInputStream.close();

            int receiverPort = message.getReceiver().getPort();
                        
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            KeyManagerFactory keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            TrustManagerFactory trustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

            // Carregar o KeyStore e o TrustStore como fez anteriormente
            KeyStore keys = KeyStore.getInstance("JKS");
            try (InputStream stream = new FileInputStream("stream.jks")) {
                keys.load(stream, "p2pmessagingapp".toCharArray());
            }
            keyManager.init(keys, "p2pmessagingapp".toCharArray());
            
            KeyStore store = KeyStore.getInstance("JKS");
            try (InputStream storeStream = new FileInputStream("storestream.jks")) {
                store.load(storeStream, "p2pmessagingapp".toCharArray());
            }
            trustManager.init(store);

            sslContext.init(keyManager.getKeyManagers(), trustManager.getTrustManagers(), null);

            // Criação do socket para conectar ao peer receptor
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            SSLSocket receiverSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", receiverPort);

            System.out.println("SIm");
            receiverSocket.startHandshake();
            System.out.println(".()"); 
            
            if (receiverSocket != null) {
                // Obter o OutputStream do socket do servidor
                OutputStream outputStream = receiverSocket.getOutputStream();
                
                // Enviar a mensagem (os bytes) através do OutputStream
                outputStream.write(serializedMessage);
                outputStream.flush();  // Garantir que os dados sejam realmente enviados
    
                receiverSocket.close();
            } else System.out.println("Client " + message.getReceiver().getId() + " not connected");
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        } */
    }
}
