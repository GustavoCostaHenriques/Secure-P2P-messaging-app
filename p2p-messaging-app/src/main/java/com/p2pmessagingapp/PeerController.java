package com.p2pmessagingapp;

import java.io.IOException;
import java.io.File;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

@Controller
public class PeerController {

    private Map<String, Peer> peerMap = new HashMap<>();

    // Endpoint for welcome page
    @GetMapping("/")
    public String welcomePage() {
        return "welcomePage";
    }

    // Endpoint for error page
    @GetMapping("/error")
    public String error() {
        return "error";
    }

    // Endpoint for submission page
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    // Endpoint to capture data submitted
    @PostMapping("/login")
    public String submitForm(
            @RequestParam("id") String id,
            @RequestParam("port") String port,
            @RequestParam("ip") String ip,
            Model model) {

        String[] client_values = new String[3];
        client_values[0] = id;
        client_values[1] = port;
        client_values[2] = ip;

        Peer peer = new Peer();
        try {
            peer.startPeer(client_values);
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (!peer.getVerificationStatus()) {
            if (peer.getRepeatedId())
                model.addAttribute("errorIdMessage", "User already exists.");

            if (peer.getRepeatedPort())
                model.addAttribute("errorPortMessage", "Port already in use.");

            model.addAttribute("errorMessage", "Invalid data, please try again.");
            return "login";
        }

        String peerId = id;

        // Store peer in peerMap with unique peerId
        peerMap.put(peerId, peer);

        return "redirect:/menu?peerId=" + peerId;
    }

    // Endpoint for menu page
    @GetMapping("/menu")
    public String menu(@RequestParam("peerId") String peerId, Model model) {
        Peer peer = peerMap.get(peerId);
        if (peer == null) {
            return "error"; // Handle case where peer is not found
        }

        String userId = peer.getValues()[0];
        String userPort = peer.getValues()[1];
        String userIp = peer.getValues()[2];

        // Add the data to the model
        model.addAttribute("userId", userId);
        model.addAttribute("userPort", userPort);
        model.addAttribute("userIp", userIp);

        // Logic to load all the chats
        File chatDir = new File("chats");
        List<String> contacts = new ArrayList<>();

        if (chatDir.exists() && chatDir.isDirectory()) {
            // Lists every file in the chats directory
            for (File file : chatDir.listFiles()) {
                String fileName = file.getName();
                if (fileName.contains("-")) {
                    String[] users = fileName.split("-");
                    if (users.length == 2) {
                        if (users[0].equals(userId)) {
                            contacts.add(users[1]);
                        } else if (users[1].equals(userId)) {
                            contacts.add(users[0]);
                        }
                    }
                }
            }
        }

        model.addAttribute("contacts", contacts);

        return "menu";
    }

    // Endpoint to handle the propose to talk with another peer
    @PostMapping("/startChat")
    @ResponseBody
    public String startChat(
            @RequestParam("peerId") String peerId,
            @RequestParam("contactName") String contactName) {
        Peer peer = peerMap.get(peerId);
        if (peer != null) {
            if (peerId.equals(contactName))
                return "your own name";
            boolean userExists = false;
            try {
                userExists = peer.checkscommunication(contactName);
            } catch (Exception e) {
            }
            if (userExists)
                return "exists";
            else
                return "not found";
        }
        return "error";
    }

    // Endpoint to handle logout and kill the peer client
    @PostMapping("/logout")
    @ResponseBody
    public String logout(@RequestParam("peerId") String peerId) {
        Peer peer = peerMap.get(peerId);
        if (peer != null) {
            try {
                peer.killClient(peer);
                peerMap.remove(peerId); // Remove peer from map when logged out
                return "success";
            } catch (IOException e) {
                return "error";
            }
        }
        return "error";
    }
}
