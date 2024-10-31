package com.p2pmessagingapp;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.tomcat.util.http.fileupload.ByteArrayOutputStream;

public class Server {

    private static InputStream inputStream; // Input stream to read data from the socket
    private final static int port = 2222;
    private static SSLServerSocket serverSocket; // SSLServerSocket to accept secure connections
    private static List<User> userList = new ArrayList<>(); // List to store users
    private static User serverUser = new User("SERVER", "localhost", 2222, null);
    private static User userNull = new User("NULL", "NULL", 0000, null);

    public static void main(String[] args) {
        try {
            System.out.println("Server will start");
            createSSLServerSocket(port);
            System.out.println("Server started");
        } catch (IOException e) {
        }
        acceptConnections();
    }

    private static void createSSLServerSocket(int port) throws IOException {
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.2"); // Create SSL context for TLS 1.2
            KeyManagerFactory keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keys = KeyStore.getInstance("JKS");

            // Load the keystore containing the server's private key
            try (InputStream stream = new FileInputStream("stream.jks")) {
                keys.load(stream, "p2pmessagingapp".toCharArray());
            }
            keyManager.init(keys, "p2pmessagingapp".toCharArray()); // Initialize the key manager with the keys

            // Load the truststore containing trusted certificates
            KeyStore store = KeyStore.getInstance("JKS");
            try (InputStream storeStream = new FileInputStream("storestream.jks")) {
                store.load(storeStream, "p2pmessagingapp".toCharArray());
            }

            TrustManagerFactory trustManager = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManager.init(store); // Initialize the trust manager with the truststore

            context.init(keyManager.getKeyManagers(), trustManager.getTrustManagers(), null); // Initialize the SSL
                                                                                              // context
            SSLServerSocketFactory factory = context.getServerSocketFactory(); // Create the server socket factory
            serverSocket = (SSLServerSocket) factory.createServerSocket(port); // Create the SSLServerSocket
            System.out.println("Criou o server socket");

        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException | CertificateException
                | KeyManagementException e) {
            e.printStackTrace(); // Print stack trace for debugging
        }
    }

    private static SSLSocket createSSLSocket(String ip, int port) {
        SSLSocket socket = null;
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

            TrustManagerFactory trustManager = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManager.init(store);

            context.init(keyManager.getKeyManagers(), trustManager.getTrustManagers(), null);
            SSLSocketFactory factory = context.getSocketFactory();
            socket = (SSLSocket) factory.createSocket(ip, port);
            System.out.println("Criou o socket");

        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException
                | CertificateException | KeyManagementException e) {
        }
        return socket;
    }

    private static void acceptConnections() {
        while (true) {
            try {
                if (serverSocket != null && !serverSocket.isClosed()) {
                    System.out.println("Server is listenning on port " + serverSocket.getLocalPort() + " e no ip "
                            + serverSocket.getInetAddress());
                }
                SSLSocket sslSocket = (SSLSocket) serverSocket.accept(); // Accept the connection and return a
                System.out.println("Server heard something");
                processMessage(sslSocket);
            } catch (IOException e) {
            }
        }
    }

    private static void processMessage(SSLSocket sslSocket) {
        Message message = null;
        Boolean killClient = false;
        try {
            inputStream = sslSocket.getInputStream(); // Get the input stream from the SSL socket
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream); // Create an ObjectInputStream for
                                                                                      // reading objects
            User user = (User) objectInputStream.readObject();

            if (user.getIp() != null && user.getPort() != 0000 && user.getReceiverId() == null) {
                boolean idExists = userList.stream()
                        .anyMatch(u -> u.getId().equals(user.getId()));

                if (!idExists) {
                    userList.add(user);
                    System.out.println(
                            "Added user " + user.getId() + " with port " + user.getPort() + " and IP " + user.getIp());
                    message = new Message(serverUser, user, "1-success", null);
                } else {
                    System.out.println("Id " + user.getId()
                            + " already exists in the list.");
                    message = new Message(serverUser, user, "1-error", null);
                }
            } else if (user.getIp() == null && user.getPort() == 0000 && user.getReceiverId() != null) {
                User foundUser = findUserById(user.getReceiverId());
                if (foundUser != userNull) {
                    System.out.println(
                            "Will send user " + foundUser.getId() + " with port " + foundUser.getPort() + " and IP "
                                    + foundUser.getIp());
                } else {
                    System.out.println("User doesn't exist");
                }
                message = new Message(serverUser, foundUser, "2", null);
            } else if (user.getIp() == null && user.getPort() == 0000 && user.getReceiverId() == null) {
                killClient = true;
                removeUserById(user.getId());
                System.out.println(
                        "Removed user " + user.getId());

            }
            System.out.println("Total users connected: " + userList.size());

            User userToSend = userNull;
            if (user.getPort() == 0000) {
                userToSend = findUserById(user.getId()); // get the info of the user that sent this request
            } else {
                userToSend = user;
            }

            if (!killClient) {
                SSLSocket sslClientSocket = createSSLSocket(userToSend.getIp(), userToSend.getPort());

                sendMessageToPeer(sslClientSocket, message);
            }

        } catch (IOException | ClassNotFoundException e) {
        }

    }

    private static void sendMessageToPeer(SSLSocket sslSocket, Message message) {
        try (OutputStream outputStream = sslSocket.getOutputStream();) {
            byte[] serializedUser = serializeMessage(message);
            // Send a message based on user data
            outputStream.write(serializedUser);
            outputStream.flush();
            sslSocket.close();
            System.out.println("Fechou o socket do client");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Serializes a Message object into a byte array for transmission.
     *
     * @param message The Message object to be serialized.
     * @return A byte array representing the serialized Message.
     * @throws IOException If an error occurs during serialization.
     */
    private static byte[] serializeMessage(Message message) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        // Serialize the Message object into a byte array
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {
            objectOutputStream.writeObject(message); // Serializes object Message
        }

        return byteArrayOutputStream.toByteArray(); // Return the byte array
    }

    private static User findUserById(String receiverId) {
        for (User u : userList) {
            if (u.getId().equals(receiverId)) {
                return u;
            }
        }
        return userNull;
    }

    private static void removeUserById(String receiverId) {
        userList.removeIf(u -> u.getId().equals(receiverId));
    }
}