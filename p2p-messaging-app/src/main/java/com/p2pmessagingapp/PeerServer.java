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

    private SSLServerSocket serverSocket; // Now it's non-static
    private Peer peer;

    public PeerServer(int portNum) throws IOException {
        createSSLServerSocket(portNum);
    }

    public void createSSLServerSocket(int port) throws IOException {
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.2");
            KeyManagerFactory keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keys = KeyStore.getInstance("JKS");
            try (InputStream stream = new FileInputStream("stream.jks")) {
                keys.load(stream, "p2pmessagingapp".toCharArray());
            }
            keyManager.init(keys, "p2pmessagingapp".toCharArray());

            KeyStore store = KeyStore.getInstance("JKS");
            try (InputStream storeStream = new FileInputStream("storestream.jks")) {
                store.load(storeStream, "p2pmessagingapp".toCharArray());
            }

            TrustManagerFactory trustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManager.init(store);

            context.init(keyManager.getKeyManagers(), trustManager.getTrustManagers(), null);
            SSLServerSocketFactory factory = context.getServerSocketFactory();
            serverSocket = (SSLServerSocket) factory.createServerSocket(port);

        } catch (NoSuchAlgorithmException | KeyStoreException | 
                UnrecoverableKeyException | CertificateException | KeyManagementException e) {
            e.printStackTrace();
        }
    }

    private static byte[] serializeMessage(Message message) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {
            objectOutputStream.writeObject(message);
        }
        return byteArrayOutputStream.toByteArray();
    }

    @Override
    public void run() {
        try {
            while (true) {
                SSLSocket sslSocket = (SSLSocket) serverSocket.accept();  // Accept incoming connection
                PeerHandler peerHandler = new PeerHandler(sslSocket);
                peerHandler.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void sendMessage(Message message) throws Exception {
        peer = new Peer(message.getReceiver().getId(), message.getReceiver().getPort());
        byte[] serializedMessage = serializeMessage(message);
        peer.sendMessage(serializedMessage);
    }
}
