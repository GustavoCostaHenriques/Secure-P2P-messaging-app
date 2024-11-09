package com.p2pmessagingapp;

import java.io.IOException;
import java.io.File;
import java.io.BufferedReader;
import java.io.FileReader;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

/**
 * PeerController class handles the endpoints for peer-to-peer communication.
 * It manages peers, provides endpoints for logging in, accessing the main menu,
 * initiating and loading chats, sending messages, and logging out.
 * 
 * This controller serves as the main interface for user interaction with the
 * application.
 */
@Controller
public class PeerController {

    private Map<String, Peer> peerMap = new HashMap<>(); // Map to store peers by their unique ID

    /**
     * Displays the welcome page.
     * 
     * @return The welcome page template name.
     */
    @GetMapping("/")
    public String welcomePage() {
        return "welcomePage";
    }

    /**
     * Displays the error page.
     * 
     * @return The error page template name.
     */
    @GetMapping("/error")
    public String error() {
        return "error";
    }

    /**
     * Displays the login page where users can submit their ID, port, and IP to
     * create a new peer session.
     * 
     * @return The login page template name.
     */
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    /**
     * Handles the login form submission, validating peer data and storing the peer
     * in the system.
     * 
     * @param id    The peer's ID.
     * @param port  The peer's port number.
     * @param ip    The peer's IP address.
     * @param model The model to pass data to the view.
     * @return Redirects to the menu page if successful, or reloads login with
     *         error messages if validation fails.
     */
    @PostMapping("/login")
    public String submitForm(
            @RequestParam("id") String id,
            @RequestParam("port") String port,
            @RequestParam("ip") String ip,
            @RequestParam(value = "topics", required = false) List<String> topics,
            Model model) {

        String[] client_values = new String[3];
        client_values[0] = id;
        client_values[1] = port;
        client_values[2] = ip;

        Peer peer = new Peer();
        try {
            peer.startPeer(client_values, topics); // Initializes the peer with provided values
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Check if peer data is valid and display appropriate error messages if not
        if (!peer.getVerificationStatus()) {
            if (peer.getRepeatedId())
                model.addAttribute("errorIdMessage", "User already exists.");

            if (peer.getRepeatedPort())
                model.addAttribute("errorPortMessage", "Port already in use.");

            model.addAttribute("errorMessage", "Invalid data, please try again.");
            return "login"; // Return to login page if validation fails
        }

        String peerId = id;

        // Store peer in peerMap with unique peerId
        peerMap.put(peerId, peer);

        return "redirect:/menu?peerId=" + peerId; // Redirect to the main menu
    }

    /**
     * Displays the main menu for a peer with options to view contacts and initiate
     * chats.
     * 
     * @param peerId The ID of the peer requesting the menu.
     * @param model  The model to pass data to the view.
     * @return The menu page template name, or error if the peer is not found.
     */
    @GetMapping("/menu")
    public String menu(@RequestParam("peerId") String peerId, Model model) {
        Peer peer = peerMap.get(peerId);
        if (peer == null)
            return "error"; // Return error page if peer is not found

        String userId = peer.getValues()[0];
        String userPort = peer.getValues()[1];
        String userIp = peer.getValues()[2];
        List<String> userInterests = peer.getInterests();

        // Pass peer details to the model for display in the menu
        model.addAttribute("userId", userId);
        model.addAttribute("userPort", userPort);
        model.addAttribute("userIp", userIp);
        model.addAttribute("userInterests", userInterests);

        // Load all previous chats with contacts and add them to the model
        File chatDir = new File("chats");
        List<String> contacts = new ArrayList<>();

        if (chatDir.exists() && chatDir.isDirectory()) {
            // Check all files in the chat directory for chat history
            for (File file : chatDir.listFiles()) {
                String fileName = file.getName();
                if (fileName.contains("-")) {
                    String[] users = fileName.split("-");
                    if (users.length == 2) {
                        if (users[0].equals(userId))
                            contacts.add(users[1]);
                        else if (users[1].equals(userId))
                            contacts.add(users[0]);
                    }
                }
            }
        }

        model.addAttribute("contacts", contacts);

        return "menu"; // Return menu page with contacts loaded
    }

    /**
     * Initiates a chat request with a specified contact if the peer is available.
     * 
     * @param peerId      The ID of the peer initiating the chat.
     * @param contactName The name of the contact to initiate chat with.
     * @return A status message indicating whether the contact was found, not
     *         found, or invalid.
     */
    @PostMapping("/startChat")
    @ResponseBody
    public String startChat(
            @RequestParam("peerId") String peerId,
            @RequestParam("contactName") String contactName) {
        Peer peer = peerMap.get(peerId);
        if (peer != null) {
            if (peerId.equals(contactName))
                return "your own name"; // Prevent user from initiating chat with themselves
            User userExists = null;
            try {
                userExists = peer.checkscommunication(contactName); // Check if contact exists
            } catch (Exception e) {
            }
            // Wait until contact status is determined
            while (userExists == null) {
                try {
                    Thread.sleep(1000); // Wait 1 second before retrying
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
            if (!userExists.getId().equals("NULL"))
                return "exists"; // Contact found
            else
                return "not found"; // Contact not found
        }
        return "error"; // Return error if peer not found
    }

    /**
     * Loads the chat history between two peers.
     * 
     * @param peerId      The ID of the peer requesting the chat history.
     * @param contactName The name of the contact whose chat history is requested.
     * @return A list of messages between the peer and the contact.
     */
    @GetMapping("/loadChat")
    @ResponseBody
    public List<String> loadChat(@RequestParam("peerId") String peerId,
            @RequestParam("contactName") String contactName) {
        List<String> messages = new ArrayList<>();
        String fileName = "chats/" + peerId + "-" + contactName;

        // Check if chat file exists with either "peerId-contactName" or
        // "contactName-peerId" format
        File chatFile = new File(fileName);
        if (!chatFile.exists())
            chatFile = new File("chats/" + contactName + "-" + peerId);

        // Read the chat file line-by-line if it exists
        if (chatFile.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(chatFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    messages.add(line); // Add each message line to the list
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return messages; // Return the list of messages
    }

    /**
     * Sends a message to a specified contact if they are available.
     * 
     * @param peerId      The ID of the peer sending the message.
     * @param contactName The name of the contact to receive the message.
     * @param message     The message content.
     * @return A status message indicating success or failure in sending the
     *         message.
     */
    @PostMapping("/sendMessage")
    @ResponseBody
    public String sendMessage(@RequestParam("peerId") String peerId,
            @RequestParam("contactName") String contactName,
            @RequestParam("message") String message) {
        Peer peer = peerMap.get(peerId);
        User receiver = null;
        try {
            receiver = peer.checkscommunication(contactName); // Check if receiver is available
        } catch (Exception e) {
        }
        // Wait until the receiver's status is known
        while (receiver == null) {
            try {
                Thread.sleep(1000); // Wait 1 second before retrying
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        if (receiver.getId().equals("NULL"))
            return "not found"; // Return if receiver not found
        else {
            peer.communicate(receiver, message); // Send the message to the receiver
            return "success"; // Return success status
        }
    }

    /**
     * Changes interests of the peer.
     * 
     * @param peerId The ID of the peer to be changed.
     * @return sucess
     */
    @PostMapping("/saveChanges")
    @ResponseBody
    public String saveChanges(
            @RequestParam("peerId") String peerId,
            @RequestBody Map<String, List<String>> topicsMap) {
        Peer peer = peerMap.get(peerId);

        List<String> topics = topicsMap.get("topics");
        if (topics.size() == 0)
            topics = null;
        if (peer != null) {
            peer.setInterests(topics);
        }

        return "success";
    }

    /**
     * Logs out the peer and removes them from the system.
     * 
     * @param peerId The ID of the peer to be logged out.
     * @return A status message indicating the success or failure of the logout.
     */
    @PostMapping("/logout")
    @ResponseBody
    public String logout(@RequestParam("peerId") String peerId) {
        Peer peer = peerMap.get(peerId);
        if (peer != null) {
            try {
                peer.killClient(peer); // Terminates the peer client process
                peerMap.remove(peerId); // Remove peer from the map
                return "success"; // Return success status
            } catch (IOException e) {
                return "error"; // Return error status if logout fails
            }
        }
        return "error"; // Return error if peer not found
    }
}
