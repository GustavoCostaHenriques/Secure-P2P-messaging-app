package com.p2pmessagingapp;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import io.github.cdimascio.dotenv.Dotenv;

public class S3Config {
    public static final AmazonS3 s3Client;

    static {
        Dotenv dotenv = Dotenv.load();

        BasicAWSCredentials awsCreds = new BasicAWSCredentials(
                dotenv.get("AWS_ACCESS_KEY_ID"),
                dotenv.get("AWS_SECRET_ACCESS_KEY"));

        s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(dotenv.get("AWS_REGION"))
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .build();
    }
}
