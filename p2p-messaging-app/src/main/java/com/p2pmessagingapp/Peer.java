/***
 * IMPORTANTE: 
 *  A lógica que o vídeo usou está um bocado diferente do que nós queremos em alguns aspetos. Por exemplo,
 *  nós não queremos que os users dêm permissão para outros users poderem mandar mensagem. O que temos que 
 *  fazer é com que todos os users tenham permissão para falar com todos os outros. E outra coisa é que neste
 *  momento é possível uma mensagem enviada por um user ir para vários outros user e não um só, também temos de 
 *  mudar isso.
 * tentar meter em SSL eu tentei mas estava meio dificil 
 * 
 */
// TODO ter um desconectar peer e ligar a outro meter coneçao tipo um gajo quer falar e falo logo n tem de esperar que i outro se ligue 


package com.p2pmessagingapp;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.json.Json;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import jakarta.xml.bind.DatatypeConverter;

public class Peer {

    private SSLSocketFactory sslSocketFactory;
    private SSLSocket sslSocket = null;

    byte[] otherPeerPubKey;
    static KeyPair keys;
    public static void main(String[] args) throws Exception {

        String[] values;
        ServerThread serverThread;
        BufferedReader bufferedReader;

        System.out.println("=> Please enter your id & port below:");
                
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
        System.out.println(keys.getPublic().getFormat()+"format " + keys.getPublic().getAlgorithm()+ " ALgo");
        createClientFile(values[0], values[1],keys.getPublic().getEncoded());

        new Peer().updateListenToPeers(bufferedReader,values[0], serverThread);
    }

    public Peer() {
        this.sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
    }
       
    
    
    public void updateListenToPeers(BufferedReader bufferedReader, String id, ServerThread serverThread) throws Exception {
        boolean validConnection= false;
        String input=null;
        String[] inputValues=null;
        PeerThread peer=null;
        while (!validConnection) {
            System.out.println("Enter localhost:port");
            System.out.println(" peers to receive messages from(s to skip):");
            input = bufferedReader.readLine();
            long count = input.chars().filter(c -> c ==':').count();
            if (count>1) {
                System.out.println("=> error: you can only connect to one user pls try again");
            }
            else{
                inputValues = input.split(" "); // Split input by spaces into host:port pairs
                validConnection=true;
            }
        }
        
        if(!input.equals("s")) {

            for (int i = 0; i < inputValues.length; i++) {
                String[] address = inputValues[i].split(":");

                try {  // Create a socket and start a PeerThread for communication
                    sslSocket =  (SSLSocket) sslSocketFactory.createSocket(address[0], Integer.valueOf(address[1]));
                    peer = new PeerThread(sslSocket,keys.getPrivate());
                    peer.start(); // Initiates a PeerThread for communication with the connected peer

                } catch (Exception e) { // Close the socket if it exists; print "invalid input" if not.
                    if (sslSocket != null) sslSocket.close();
                    else System.out.println("invalid input");
                }
            }
        }
        // Handles user communication with connected peers.
        communicate(bufferedReader, id, serverThread, peer);
    }
    


    /**
    * Facilitates communication with peers by reading user input and sending messages.
    *
    * @param bufferedReader The BufferedReader to read user input from the console.
    * @param id The unique identifier of the user (peer).
    * @param serverThread The ServerThread instance responsible for sending messages to peers.
    */

    public void communicate(BufferedReader bufferedReader, String id, ServerThread serverThread,PeerThread peer) {

        try {
            System.out.println("You can now communicate (e to exit, c to change,k to send pubKey)");
            boolean flag = true;
            boolean pubKeySent= false;
            while(flag) {

                String message = bufferedReader.readLine();
                
                if(message.equals("e")) { //exit the communication
                    flag = false;
                    break;

                } else if (message.equals("c")) { //change the peer
                    endConnection();
                    this.sslSocket.close();
                    updateListenToPeers(bufferedReader, id, serverThread);
               
                } 
                else if (message.equals("k")){
                    sendPubKey(id, serverThread);
                    pubKeySent=true;
                }    else {
                    if (pubKeySent) {
                        System.out.println(peer.getReceiverPKey().toString());
                        byte[] receiverPKey= peer.getReceiverPKey();
                        StringWriter stringWriter = new StringWriter();
                        message = bytesToString(encryptRSA(message, receiverPKey));
                    // Creates a JSON object with the user's ID and message for transmission.
                    Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder() 
                                                .add("id", id)
                                                .add("message", message)
                                                .build());
                    serverThread.sendMessage(stringWriter.toString());
                    }
                    else{
                        System.out.println("=>error you have to send your pubkey before sending any messages");
                    }
                }
            }
            System.exit(0);
        } catch (Exception e) { e.printStackTrace(); }
    }

    private static void createClientFile(String id, String port, byte[] key) {
        try {
            File dir = new File("clients");
            if (!dir.exists()) {
                dir.mkdir(); // Criar a diretoria se não existir
            }

            File file = new File(dir, id);
            BufferedWriter writer = new BufferedWriter(new FileWriter(file));
            writer.write(port); // Escrever a porta no ficheiro
            writer.write(System.getProperty("line.separator"));
            writer.write(DatatypeConverter.printHexBinary(key));
            writer.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeys()
        throws Exception
        {
            SecureRandom secureRandom = new SecureRandom();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048,secureRandom);
            return keyPairGenerator.generateKeyPair();
        }

    private static boolean fileAndPortVerification( String[] values){
        String errorMessage;
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
            if(errorMessage.equals("")) return true;
            System.out.println("=> " + errorMessage + " already in use, please insert a different " + errorMessage + ":");
            return false;
    }

    private static void sendPubKey(String id, ServerThread serverThread){
        StringWriter stringWriter = new StringWriter();
        byte[] pubKeytoSend = keys.getPublic().getEncoded();
        String message = Base64.getEncoder().encodeToString(pubKeytoSend);          
        // Creates a JSON object with the user's ID and message for transmission.
        Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                                    .add("id", id)
                                    .add("key", message)
                                    .build());
        serverThread.sendMessage(stringWriter.toString());
    } 

    public static byte[] encryptRSA(String message, byte[] encodedPbKey) throws Exception {
        PublicKey publicKey= byteToPublicKey(encodedPbKey); 
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    public String bytesToString(byte[] bytes){
        return Base64.getEncoder().encodeToString(bytes);
    }

    public byte[] stringToBytes(String string){
        return Base64.getDecoder().decode(string);
    }

    public static PublicKey byteToPublicKey(byte[] encodedPbKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPbKey);
        return keyFactory.generatePublic(publicKeySpec);
    }

    private void endConnection(){
        
    }
}
