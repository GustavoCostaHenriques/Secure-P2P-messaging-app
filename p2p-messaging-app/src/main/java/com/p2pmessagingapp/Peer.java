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
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.json.Json;
import javax.xml.bind.DatatypeConverter; // Import regular Socket instead of SSLSocket

public class Peer {
    
    private Socket socket; // Change from SSLSocket to Socket
    byte[] otherPeerPubKey;
    static KeyPair keys;

    public static void main(String[] args) throws Exception {

        String[] values;
        ServerThread serverThread;
        BufferedReader bufferedReader;
        System.out.println("=> Please enter your id & port below:(Ex: Valeta 6969) ");

        while (true) {
            bufferedReader = new BufferedReader(new InputStreamReader(System.in));
            values = bufferedReader.readLine().split(" "); // Reads and splits user input details
            boolean verificationStatus = fileAndPortVerification(values);
            if (verificationStatus) {
                break;
            }
        }
        serverThread = new ServerThread(values[1]);
        serverThread.start();
        keys = generateKeys();
        System.out.println(keys.getPublic().getFormat() + " format " + keys.getPublic().getAlgorithm() + " ALgo");
        createClientFile(values[0], values[1], keys.getPublic().getEncoded());
        createUsersFile(values[1]);
        new Peer().updateListenToPeers(bufferedReader, values[0], serverThread);
    }

    public Peer() {
        // No need for SSLSocketFactory now
    }

    public void updateListenToPeers(BufferedReader bufferedReader, String id, ServerThread serverThread) throws Exception {
        boolean validConnection = false;
        String input = null;
        String[] inputValues = null;
        PeerThread peer = null;
    
        // Continue prompting until the user enters a valid connection string in the format 'localhost:port'
        while (!validConnection) {
            System.out.println("Enter localhost:port to connect to peers (s to skip):");
            input = bufferedReader.readLine();
    
            if (input.equals("s")) {  // If user chooses to skip, break the loop
                break;
            }
    
            // Check if the input has the correct format 'localhost:port'
            long count = input.chars().filter(c -> c == ':').count();
    
            if (count == 1) {
                inputValues = input.split(":"); // Split input into 'localhost' and 'port'
    
                if (inputValues.length == 2) {
                    try {
                        // Validate the port format and range
                        int port = Integer.parseInt(inputValues[1]);
                        if (port > 0 && port <= 65535) {
                            // If the port is valid, try to establish the connection
                            socket = new Socket(inputValues[0], port);
                            peer = new PeerThread(socket, keys.getPrivate());
                            peer.start(); // Start PeerThread to communicate with the peer connected
                            validConnection = true; // Connection established successfully
                        } else {
                            System.out.println("=> error: port must be a number between 1 and 65535.");
                        }
                    } catch (NumberFormatException e) {
                        System.out.println("=> error: port must be a valid number.");
                    } catch (IOException e) {
                        System.out.println("=> error: connection failed, please try again.");
                        // No need to close socket here as it's not established yet
                    }
                } else {
                    System.out.println("=> error: incorrect format, please enter 'localhost:port'");
                }
            } else {
                System.out.println("=> error: incorrect format, please enter 'localhost:port'");
            }
        }
    
        // If a valid connection was established, handle communication
        if (validConnection) {
            communicate(bufferedReader, id, serverThread, peer);
        }
    }
    


    public void communicate(BufferedReader bufferedReader, String id, ServerThread serverThread, PeerThread peer) {
        try {
            System.out.println("You can now communicate (e to exit, c to change, k to send pubKey)");
            boolean flag = true;
            boolean pubKeySent = false;
            while (flag) {
                String message = bufferedReader.readLine();
                System.out.println("Message sended: " + message); // Debug print

                if (message.equals("e")) { // exit the communication
                    flag = false;
                    break;
                } else if (message.equals("c")) { // change the peer
                    endConnection();
                    this.socket.close();
                    updateListenToPeers(bufferedReader, id, serverThread);
                } else if (message.equals("k")) {
                    sendPubKey(id, serverThread);
                    pubKeySent = true;
                } else {
                    if (pubKeySent) {
                        // System.out.println(peer.getReceiverPKey().toString());
                        byte[] receiverPKey = peer.getReceiverPKey();
                        StringWriter stringWriter = new StringWriter();
                        String hash = bytesToString(Create_Digital_Signature(stringToBytes(message), keys.getPrivate()));
                        message = bytesToString(encryptPubRSA(message, receiverPKey));
                        // Creates a JSON object with the user's ID and message for transmission.
                        Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                                .add("id", id)
                                .add("message", message)
                                .add("hash", hash)
                                .build());
                        serverThread.sendMessage(stringWriter.toString());
                    } else {
                        System.out.println("=> error: you have to send your pubkey before sending any messages");
                    }
                }
            }
            System.exit(0);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void createClientFile(String id, String port, byte[] key) {
        try {
            File dir = new File("clients");
            if (!dir.exists()) {
                dir.mkdir(); // Create the directory if it does not exist
            }

            File file = new File(dir, id);
            BufferedWriter writer = new BufferedWriter(new FileWriter(file));
            writer.write(port); // write the port in the file
            writer.write(System.getProperty("line.separator"));
            writer.write(DatatypeConverter.printHexBinary(key)); // write the public key in the file
            writer.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void createUsersFile(String port) {
        File myObj = null;
        try {
            myObj = new File("Ports");
            if (myObj.createNewFile()) {
                System.out.println("File created: " + myObj.getName());
            } else {
                System.out.println("File already exists.");
            }
            Scanner sc = new Scanner(myObj);
            BufferedWriter writer = new BufferedWriter(new FileWriter(myObj, true)); // append mode
            while (sc.hasNextLine()) {
                sc.nextLine();
            }
            sc.close();
            writer.write(port); // write the port in the file
            writer.write(System.getProperty("line.separator"));
            writer.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeys() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    private static boolean fileAndPortVerification(String[] values) {
        // Check if the correct number of values was provided
        if (values.length != 2) {
            System.out.println("=> error: input must be in the format 'id port' (e.g., Valeta 6969).");
            return false;
        }
    
        String errorMessage = "";
        File filename = new File("clients/" + values[0]); // Check if the ID already exists
        if (filename.exists()) errorMessage = "ID";
    
        // Check if the second value (port) is a valid number
        try {
            int port = Integer.parseInt(values[1]);
            if (port <= 0 || port > 65535) { // Limit the port to a range between 1 and 65535
                System.out.println("=> error: port must be a number between 1 and 65535.");
                return false;
            }
        } catch (NumberFormatException e) {
            System.out.println("=> error: port must be a valid number.");
            return false;
        }
    
        // Check if the port is already in use
        File folder = new File("clients");
        if (folder.exists() && folder.isDirectory()) {
            File[] files = folder.listFiles(); // Iterate through the files
            if (files != null) {
                for (File file : files) {
                    if (file.isFile()) {
                        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                            String filePort = reader.readLine(); // Read the file content (port)
                            if (filePort.equals(values[1])) { // Check if the port already exists
                                if (errorMessage.equals("")) errorMessage = "Port";
                                else errorMessage = "ID and Port";
                            }
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
    
        if (errorMessage.equals("")) return true;
        System.out.println("=> " + errorMessage + " already in use, please insert a different " + errorMessage + ":");
        return false;
    }
    
    

    private static void sendPubKey(String id, ServerThread serverThread) {
        StringWriter stringWriter = new StringWriter();
        byte[] pubKeyToSend = keys.getPublic().getEncoded(); // convert public key to an array of bytes
        String message = Base64.getEncoder().encodeToString(pubKeyToSend); // Encodes the public key bytes into a (Base64) string         
        // Creates a JSON object with the user's ID and message for transmission.
        Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                .add("id", id)
                .add("key", message)
                .build());
        serverThread.sendMessage(stringWriter.toString());
    }

    public static byte[] encryptPubRSA(String message, byte[] encodedPbKey) throws Exception {
        PublicKey publicKey = byteToPublicKey(encodedPbKey);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    public String bytesToString(byte[] bytes) {
        return Base64.getMimeEncoder().encodeToString(bytes);
    }

    public byte[] stringToBytes(String string) {
        int paddingCount = (4 - string.length() % 4) % 4;
        if (paddingCount > 0) {
            string += "=".repeat(paddingCount); // Adiciona o padding necessário
        }
        return Base64.getMimeDecoder().decode(string);
    }

    public static PublicKey byteToPublicKey(byte[] encodedPbKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPbKey);
        return keyFactory.generatePublic(publicKeySpec);
    }

    private void endConnection() {
        // Add logic for disconnecting from the peer if needed
    }

    public static byte[] encryptPrivRSA(String message, PrivateKey privateKey) throws Exception { 
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(message.getBytes());
    }

    private static String makeHash(String text) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
        String encoded = Base64.getEncoder().encodeToString(hash);
        return encoded;
    }
     public static byte[] Create_Digital_Signature( byte[] input, PrivateKey Key) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA"); 
        signature.initSign(Key); 
        signature.update(input); 
        return signature.sign(); 
    } 
}
