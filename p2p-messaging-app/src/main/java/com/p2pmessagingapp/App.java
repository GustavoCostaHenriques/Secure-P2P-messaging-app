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
     * configuration.
     *
     * @param args Command-line arguments that may be passed to the application on
     *             startup.
     */
    public static void main(String[] args) {
        SpringApplication.run(App.class, args); // Launches the Spring Boot application
    }
}
