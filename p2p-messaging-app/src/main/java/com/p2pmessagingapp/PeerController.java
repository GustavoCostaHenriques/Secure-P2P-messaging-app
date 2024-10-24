package com.p2pmessagingapp;

import java.io.IOException;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class PeerController {
    private Peer peer;

    // Endpoint for welcome page
    @GetMapping("/")
    public String welcomePage() {
        return "welcomePage";
    }

    // Endpoint for submission page
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    // Endpoint to capture data submited
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

        peer = new Peer();
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

        return "redirect:/menu";
    }

    // Endpoint for menu page
    @GetMapping("/menu")
    public String menu(Model model) {
        String userId = peer.getValues()[0];
        String userPort = peer.getValues()[1];
        String userIp = peer.getValues()[2];

        // Add the data to the model
        model.addAttribute("userId", userId);
        model.addAttribute("userPort", userPort);
        model.addAttribute("userIp", userIp);
        return "menu";
    }

    // Endpoint to handle logout and kill the peer client
    @PostMapping("/logout")
    @ResponseBody
    public String logout() {
        if (peer != null) {
            try {
                peer.killClient();
                return "success";
            } catch (IOException e) {
                return "error";
            }
        }
        return "error";
    }
}