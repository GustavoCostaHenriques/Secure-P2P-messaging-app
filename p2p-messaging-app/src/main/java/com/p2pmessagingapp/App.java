package com.p2pmessagingapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * The main application class for the P2P messaging application.
 * This class is responsible for bootstrapping and starting the Spring Boot
 * application.
 */
@SpringBootApplication // Marks this class as the main entry point for Spring Boot and enables
                       // component scanning
public class App {

    /**
     * The main method, which serves as the entry point for the Spring Boot
     * application.
     * This method runs the Spring Boot application using the provided
     * configuration or cleans the existing database in the cloud.
     *
     * @param args Command-line arguments that may be passed to the application on
     *             startup.
     */
    public static void main(String[] args) {

        // Checks if it is to clear a user from the cloud
        if (args.length > 0) {
            String[] parts = args[0].split("_");
            String userId = parts[1];
            System.out.println("Clearing all cloud data...");
            CloudCleaner.main(new String[] { userId }); //
            System.out.println("Cloud data cleared successfully.");

            return; // Leaves application after cleaning data
        }

        SpringApplication.run(App.class, args); // Launches SpringBoot Application
        Server.main(null);
    }
}
