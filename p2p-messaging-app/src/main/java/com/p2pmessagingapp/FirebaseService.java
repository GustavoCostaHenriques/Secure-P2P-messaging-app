package com.p2pmessagingapp;

import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.firestore.CollectionReference;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.QueryDocumentSnapshot;
import com.google.firebase.cloud.FirestoreClient;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FirebaseService {
    private Firestore db = null; // Initialize to null by default

    public FirebaseService() {
        try {
            if (FirebaseApp.getApps().isEmpty()) {
                FileInputStream serviceAccount = new FileInputStream(
                        "src/main/resources\\cryptalink-271d1-481d81d40630.json");

                FirebaseOptions options = FirebaseOptions.builder()
                        .setCredentials(GoogleCredentials.fromStream(serviceAccount))
                        .build();

                FirebaseApp.initializeApp(options);
            }
            db = FirestoreClient.getFirestore();
        } catch (IllegalStateException e) {
            db = FirestoreClient.getFirestore();
        } catch (IOException e) {
            System.err.println("Failed to initialize Firebase: " + e.getMessage());
        }
    }

    public Firestore getDb() {
        return db;
    }

    /**
     * Save a message to Firebase, creating nested collections based on the provided
     * path.
     *
     * @param pathElements   List of strings representing the hierarchical path.
     * @param messageContent The content of the message to save.
     */
    public void saveMessage(String bucket, String objectKey, String messageContent) {
        try {
            Map<String, Object> messageData = new HashMap<>();
            messageData.put("content", messageContent);

            db.collection(bucket).document(objectKey).set(messageData).get();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error saving message to Firestore.");
        }
    }

    /**
     * Save parts of a key across different collections in Firestore.
     *
     * @param buckets  Array of bucket names (collections).
     * @param userId   The ID of the user (used as part of the document path).
     * @param keyParts Map where each part of the key is stored (e.g., <PartNumber,
     *                 KeyPart>).
     */
    public void saveKeyParts(String[] buckets, String userId, Map<Integer, byte[]> keyParts) {
        int bucketIndex = 0;

        for (Map.Entry<Integer, byte[]> keyPartEntry : keyParts.entrySet()) {
            try {
                // Encode the key part to Base64 to ensure it's a valid string for Firestore
                String base64KeyPart = Base64.getEncoder().encodeToString(keyPartEntry.getValue());

                // Prepare data to save
                Map<String, Object> keyData = new HashMap<>();
                keyData.put("keyPart", base64KeyPart);
                keyData.put("partNumber", keyPartEntry.getKey());

                // Determine the bucket (collection) for this part
                String bucket = buckets[bucketIndex % buckets.length]; // Cycle through buckets

                // Save the key part using a clean document structure
                db.collection(bucket)
                        .document("KEYS") // Document for the user
                        .collection(userId) // Subcollection for keys
                        .document("part_" + keyPartEntry.getKey()) // Document for the specific key part
                        .set(keyData);

                // Move to the next bucket
                bucketIndex++;

            } catch (Exception e) {
                e.printStackTrace();
                System.err.println("Error saving key part " + keyPartEntry.getKey() + " for user " + userId + ": "
                        + e.getMessage());
            }
        }
    }

    public List<String> listObjects(String bucket, String prefix) {
        List<String> objectKeys = new ArrayList<>();
        try {
            // List all documents in the specified collection
            db.collection(bucket)
                    .listDocuments()
                    .forEach(documentReference -> {
                        String documentPath = documentReference.getPath();
                        if (documentPath.startsWith(prefix)) {
                            objectKeys.add(documentPath);
                        }
                    });
        } catch (Exception e) {
            System.err.println("Error listing objects in Firebase: " + e.getMessage());
        }
        return objectKeys;
    }

    public void deleteObjects(List<String> bucketNames, String userId, Firestore db) {
        try {
            for (String bucketName : bucketNames) {
                String userPrefix = bucketName + "/CHATS/" + userId; // Specific prefix of the user.

                CollectionReference collectionRef = db.collection(userPrefix);

                List<QueryDocumentSnapshot> documents = collectionRef.get().get().getDocuments();

                for (DocumentSnapshot doc : documents) {
                    db.collection(userPrefix).document(doc.getId()).delete().get();
                    System.out.println("Deleted document with ID: " + doc.getId());
                }

            }

            for (String bucketName : bucketNames) {
                String userPrefix = bucketName + "/KEYS/" + userId; // Specific prefix of the user.

                CollectionReference collectionRef = db.collection(userPrefix);

                List<QueryDocumentSnapshot> documents = collectionRef.get().get().getDocuments();

                for (DocumentSnapshot doc : documents) {
                    db.collection(userPrefix).document(doc.getId()).delete().get();
                    System.out.println("Deleted document with ID: " + doc.getId());
                }

            }
        } catch (Exception e) {
            System.err.println("Error deleting objects: " + e.getMessage());
        }
    }

}
