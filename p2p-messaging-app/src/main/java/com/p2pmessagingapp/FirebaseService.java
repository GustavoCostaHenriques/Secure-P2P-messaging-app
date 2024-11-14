package com.p2pmessagingapp;

import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.firestore.Firestore;
import com.google.firebase.cloud.FirestoreClient;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class FirebaseService {
    private Firestore db = null; // Initialize to null by default

    public FirebaseService() {
        try {
            if (FirebaseApp.getApps().isEmpty()) {
                FileInputStream serviceAccount = new FileInputStream(
                        "src/main/resources\\cryptalink-271d1-firebase-adminsdk-zt96q-5b9d7e28c8.json");

                FirebaseOptions options = FirebaseOptions.builder()
                        .setCredentials(GoogleCredentials.fromStream(serviceAccount))
                        .build();

                FirebaseApp.initializeApp(options);
            }
            db = FirestoreClient.getFirestore();
        } catch (IOException e) {
            System.err.println("Failed to initialize Firebase: " + e.getMessage());
        }
    }

    // Method to save a message to Firebase Storage
    public void saveMessage(String messageContent, String objectKey) {
        try {
            // Create a map to store the message content
            Map<String, Object> messageData = new HashMap<>();
            messageData.put("content", messageContent); // Wrap the content in a map

            // Store the conversation object in multiple Firestore collections
            db.collection("bucket_chats1").document(objectKey).set(messageData).get();
            db.collection("bucket_chats2").document(objectKey).set(messageData).get();
            db.collection("bucket_chats3").document(objectKey).set(messageData).get();
            db.collection("bucket_chats4").document(objectKey).set(messageData).get();

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error saving message to Firestore.");
        }
    }
}
