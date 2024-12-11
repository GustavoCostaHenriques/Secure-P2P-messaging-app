package com.p2pmessagingapp;

import java.util.Arrays;
import java.util.List;

import com.amazonaws.services.s3.model.ListObjectsV2Request;
import com.amazonaws.services.s3.model.ListObjectsV2Result;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.google.cloud.firestore.Firestore;

import io.github.cdimascio.dotenv.Dotenv;

public class CloudCleaner {

    public static void main(String[] args) {
        String userId = args[0];
        clearAllCloudStorage(userId);
    }

    /**
     * Clears all cloud storage, deleting directories CHATS/ and KEYS/ from AWS,
     * Firebase, and Azure, from a specific user.
     * 
     * @param userId The user that is going to be erased from the cloud.
     */
    public static void clearAllCloudStorage(String userId) {
        clearAWSStorage(userId); // Clears AWS storage
        clearFirebaseStorage(userId); // Clears Firebase storage
        clearAzureStorage(userId); // Clears Azure storage
    }

    /**
     * Clears AWS storage by deleting all objects under CHATS/ and KEYS/ prefixes in
     * all configured buckets.
     * 
     * @param userId The user that is going to be erased from the cloud.
     */
    public static void clearAWSStorage(String userId) {
        try {
            // AWS buckets
            String[] awsBuckets = {
                    Dotenv.load().get("S3_BUCKET_NAME_1"),
                    Dotenv.load().get("S3_BUCKET_NAME_2"),
                    Dotenv.load().get("S3_BUCKET_NAME_3"),
                    Dotenv.load().get("S3_BUCKET_NAME_4")
            };

            String[] prefixes = { "CHATS/" + userId + "/", "KEYS/" + userId };

            // Iterate over each bucket and prefix
            for (String bucket : awsBuckets) {
                for (String prefix : prefixes) {
                    // List objects in the bucket with the specified prefix
                    ListObjectsV2Request request = new ListObjectsV2Request()
                            .withBucketName(bucket)
                            .withPrefix(prefix);

                    ListObjectsV2Result result;
                    do {
                        result = S3Config.s3Client.listObjectsV2(request);
                        List<S3ObjectSummary> objects = result.getObjectSummaries();

                        // Delete each object listed
                        for (S3ObjectSummary object : objects) {
                            S3Config.s3Client.deleteObject(bucket, object.getKey());
                        }

                        // Continue listing if there are more results
                        request.setContinuationToken(result.getNextContinuationToken());
                    } while (result.isTruncated());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("------------------- AWS clear -------------------");
    }

    /**
     * Clears Firebase storage by deleting all objects under CHATS/ and KEYS/
     * prefixes in all configured containers.
     * 
     * @param userId The user that is going to be erased from the cloud.
     */
    public static void clearFirebaseStorage(String userId) {
        // Firebase buckets
        FirebaseService firebaseService = new FirebaseService();
        Firestore db = firebaseService.getDb();
        firebaseService
                .deleteObjects(Arrays.asList("bucket_chats1", "bucket_chats2", "bucket_chats3", "bucket_chats4"),
                        userId, db);
        System.out.println("------------------- Firebase clear -------------------");
    }

    /**
     * Clears Azure storage by deleting all objects under CHATS/ and KEYS/ prefixes
     * in all configured containers.
     * 
     * @param userId The user that is going to be erased from the cloud.
     */
    public static void clearAzureStorage(String userId) {
        // Azure containers
        String[] azureContainers = { "bucket-chats1", "bucket-chats2", "bucket-chats3", "bucket-chats4" };

        AzureBlobService azureBlobService = new AzureBlobService();

        String userPrefixCHAT = "CHATS/" + userId + "/";
        // Deleting Azure objects
        for (String container : azureContainers) {
            List<String> objectKeys = azureBlobService.listBlobsInDirectory(container, userPrefixCHAT);

            for (String blobKey : objectKeys) {
                try {
                    azureBlobService.deleteBlob(container, blobKey);
                    System.out.println("Deleted blob: " + blobKey);
                } catch (Exception e) {
                    System.err.println("Error deleting blob " + blobKey + ": " + e.getMessage());
                }
            }
        }

        String userPrefixKEY = "KEYS/" + userId;
        // Deleting Azure objects
        for (String container : azureContainers) {
            List<String> objectKeys = azureBlobService.listBlobsInDirectory(container, userPrefixKEY);

            for (String blobKey : objectKeys) {
                try {
                    azureBlobService.deleteBlob(container, blobKey);
                    System.out.println("Deleted blob: " + blobKey);
                } catch (Exception e) {
                    System.err.println("Error deleting blob " + blobKey + ": " + e.getMessage());
                }
            }
        }
        System.out.println("------------------- Azure clear -------------------");
    }
}