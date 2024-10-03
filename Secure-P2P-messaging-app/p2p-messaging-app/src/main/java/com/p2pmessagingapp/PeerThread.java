package com.p2pmessagingapp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import javax.net.ssl.SSLSocket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.json.Json;
import javax.json.JsonObject;


public class PeerThread extends Thread {
    private BufferedReader bufferedReader;
    private static byte[] receiverPKey;
    private PrivateKey privateKey;
    
    public PeerThread(SSLSocket sslSocket,PrivateKey pKey) throws IOException {
        bufferedReader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
        this.privateKey= pKey;
    }
    public void run() {
        boolean flag = true;
        while(flag) {
            try {
                JsonObject jsonObject = Json.createReader(bufferedReader).readObject();
                if (jsonObject.containsKey("id") && jsonObject.containsKey("key")) {
                    System.out.println(jsonObject.getString("id")+" key was recieved");
                    receiverPKey = Base64.getDecoder().decode(jsonObject.getString("key"));
                }
                else if(jsonObject.containsKey("id")){
                    String cleanMessage = decryptRSA(stringToBytes(jsonObject.getString("message")), privateKey);
                    if(!checkHash(jsonObject)){
                        System.out.println("["+jsonObject.getString("id")+"]: "+cleanMessage);
                    }
                    else System.out.println("dif hash");
                }
                else{
                    System.out.println("hash was diffetent");
                }
            } catch(Exception e) {
                flag = false;
                interrupt();
            }
        }
    }
    public byte[] getReceiverPKey(){
        return receiverPKey;
    }
    private static String decryptRSA(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    } 
    
    public static byte[] stringToBytes(String string){
        return Base64.getDecoder().decode(string);
    }
    private static PublicKey byteToPublicKey(byte[] encodedPbKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPbKey);
        return keyFactory.generatePublic(publicKeySpec);
    } 
    private static byte[] decryptPKRSA(String message, byte[] receiverPKey) throws Exception{
        byte[] encryptedMessage = stringToBytes(message); 
        PublicKey publicKey = byteToPublicKey(receiverPKey);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return decryptedBytes;
    }

    private static boolean checkHash(JsonObject jObject) throws Exception {
        String sentHash = bytesToString(decryptPKRSA(jObject.getString("hash"),receiverPKey));
        String messageHash = makeHash(jObject.getString("message"));
        System.out.println(sentHash);
        System.out.println(" ");
        System.err.println(messageHash);
        return sentHash.equals(messageHash);
    }

    public static String bytesToString(byte[] bytes){
        return Base64.getEncoder().encodeToString(bytes);
    }

     private static String makeHash(String text) throws NoSuchAlgorithmException{
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
        String encoded = Base64.getEncoder().encodeToString(hash);
        return encoded;
    }

}