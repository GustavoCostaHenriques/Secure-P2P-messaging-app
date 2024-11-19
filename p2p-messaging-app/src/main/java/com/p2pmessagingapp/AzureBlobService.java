package com.p2pmessagingapp;

import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobContainerClientBuilder;

import java.io.ByteArrayInputStream;

public class AzureBlobService {
    private final String connectionString = "DefaultEndpointsProtocol=https;AccountName=cryptalink;AccountKey=ifMm9s70Fgjp+82Xr4JPMmkuo/fjAqCcabVRIg9LqI4xo3lesXi6hmqAwknZqlF53dgOmSUtwuwy+ASt3ssMJw==;EndpointSuffix=core.windows.net";

    public void uploadMessage(String containerName, String objectKey, ByteArrayInputStream inputStream) {
        BlobContainerClient containerClient = new BlobContainerClientBuilder()
                .connectionString(connectionString)
                .containerName(containerName)
                .buildClient();

        BlobClient blobClient = containerClient.getBlobClient(objectKey);
        blobClient.upload(inputStream, inputStream.available(), true);

    }
}
