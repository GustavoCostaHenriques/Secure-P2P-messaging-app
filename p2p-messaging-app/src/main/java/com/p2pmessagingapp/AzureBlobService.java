package com.p2pmessagingapp;

import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobContainerClientBuilder;
import com.azure.storage.blob.models.BlobItem;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

public class AzureBlobService {
    private final String connectionString = "DefaultEndpointsProtocol=https;AccountName=cryptalink;AccountKey=ifMm9s70Fgjp+82Xr4JPMmkuo/fjAqCcabVRIg9LqI4xo3lesXi6hmqAwknZqlF53dgOmSUtwuwy+ASt3ssMJw==;EndpointSuffix=core.windows.net";

    /**
     * Uploads a message to Azure Blob Storage.
     *
     * @param containerName The name of the Azure container (bucket).
     * @param objectKey     The key (name) of the blob.
     * @param inputStream   The InputStream containing the data to upload.
     */
    public void uploadMessage(String containerName, String objectKey, ByteArrayInputStream inputStream) {
        BlobContainerClient containerClient = new BlobContainerClientBuilder()
                .connectionString(connectionString)
                .containerName(containerName)
                .buildClient();

        BlobClient blobClient = containerClient.getBlobClient(objectKey);
        blobClient.upload(inputStream, inputStream.available(), true);

    }

    /**
     * Lists all blobs (files) in a specific directory (prefix).
     *
     * @param containerName The name of the Azure container (bucket).
     * @param prefix        The directory or prefix to search, e.g.,
     *                      "CHATS/<userId>/".
     * @return A list of blob names (keys) under the given prefix.
     */
    public List<String> listBlobsInDirectory(String containerName, String prefix) {
        List<String> blobNames = new ArrayList<>();
        try {
            // Create a client for the container
            BlobContainerClient containerClient = new BlobContainerClientBuilder()
                    .connectionString(connectionString)
                    .containerName(containerName)
                    .buildClient();

            // List all blobs with the specified prefix
            for (BlobItem blobItem : containerClient.listBlobsByHierarchy(prefix)) {
                blobNames.add(blobItem.getName());
            }
        } catch (Exception e) {
            System.err.println("Error listing blobs: " + e.getMessage());
            e.printStackTrace();
        }
        return blobNames;
    }

    /**
     * Fetches the content of a blob as a byte array.
     *
     * @param containerName The name of the container.
     * @param blobName      The name of the blob (objectKey).
     * @return Byte array containing the blob's content.
     */
    @SuppressWarnings("deprecation")
    public byte[] fetchBlobContent(String containerName, String blobName) {
        try {
            // Create a client for the container
            BlobContainerClient containerClient = new BlobContainerClientBuilder()
                    .connectionString(connectionString)
                    .containerName(containerName)
                    .buildClient();

            // Get a client for the specific blob
            BlobClient blobClient = containerClient.getBlobClient(blobName);

            // Download the blob's content to a byte array
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            blobClient.download(outputStream);
            return outputStream.toByteArray();
        } catch (Exception e) {
            System.err.println("Error fetching blob content: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    public void deleteBlob(String containerName, String blobKey) {
        try {
            // Criação do cliente de container
            BlobContainerClient containerClient = new BlobContainerClientBuilder()
                    .connectionString(connectionString)
                    .containerName(containerName)
                    .buildClient();

            // Obter o cliente do blob e deletar o blob
            BlobClient blobClient = containerClient.getBlobClient(blobKey);
            blobClient.delete();
            System.out.println("Blob deleted: " + blobKey);
        } catch (Exception e) {
            System.err.println("Error deleting blob: " + e.getMessage());
        }
    }
}
