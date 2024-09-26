package com.p2pmessagingapp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;

import javax.json.Json;
import javax.json.JsonObject;


public class PeerThread extends Thread {
    private BufferedReader bufferedReader;
    public PeerThread(Socket socket) throws IOException {
        bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    }
    public void run() {
        boolean flag = true;
        while(flag) {
            try {
                JsonObject jsonObject = Json.createReader(bufferedReader).readObject();
                if(jsonObject.containsKey("id"))
                    System.out.println("["+jsonObject.getString("id")+"]: "+jsonObject.getString("message"));
            } catch(Exception e) {
                flag = false;
                interrupt();
            }
        }
    }
}
