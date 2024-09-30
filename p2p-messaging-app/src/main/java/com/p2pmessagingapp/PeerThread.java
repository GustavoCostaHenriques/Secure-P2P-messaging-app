package com.p2pmessagingapp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.json.Json;
import javax.json.JsonObject;


public class PeerThread extends Thread {
    private BufferedReader bufferedReader;
    private byte[] receiverPKey;
    private PrivateKey privateKey;
    public PeerThread(Socket socket,PrivateKey pKey) throws IOException {
        bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
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
                    System.out.println("["+jsonObject.getString("id")+"]: "+cleanMessage);
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

    public byte[] stringToBytes(String string){
        return Base64.getDecoder().decode(string);
    }

}