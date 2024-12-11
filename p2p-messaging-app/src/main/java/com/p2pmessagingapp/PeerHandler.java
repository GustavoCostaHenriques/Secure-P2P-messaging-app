package com.p2pmessagingapp;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;

import javax.net.ssl.SSLSocket;

/**
 * The PeerHandler class extends Thread to handle incoming messages from a
 * connected peer.
 * It reads messages over a secure SSL socket and processes them accordingly.
 */
public class PeerHandler extends Thread {
    private InputStream inputStream; // Input stream to read data from the socket
    private SSLSocket sslSocket; // SSL socket for secure communication with the peer
    private PeerServer peerServer; // PeerServer that created this peerHandler

    /**
     * Constructs a PeerHandler instance with the specified SSL socket.
     *
     * @param sslSocket The SSL socket connected to the peer.
     * @throws IOException If an error occurs while obtaining the input stream from
     *                     the socket.
     */
    public PeerHandler(SSLSocket sslSocket, PeerServer peerServer) throws IOException {
        this.sslSocket = sslSocket; // Initialize the SSL socket
        this.peerServer = peerServer; // Initialize the peerServer
    }

    /**
     * Constructs a PeerHandler instance.
     */
    public PeerHandler() {
    }

    /**
     * The main method that runs in the thread to listen for and process incoming
     * messages.
     * It continuously reads messages from the input stream and prints them to the
     * console.
     */
    @Override
    public void run() {
        try {
            this.inputStream = sslSocket.getInputStream(); // Get the input stream from the SSL socket
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream); // Create an ObjectInputStream for
                                                                                      // reading objects

            // Infinite loop to read incoming messages
            while (true) {
                // Block until an object is available to be read
                Message message = (Message) objectInputStream.readObject();
                if (message.getSender().getId().equals("SERVER")) {
                    if (message.getGroupKey() != null)
                        peerServer.setGroupKeyToPeer(message.getGroupKey());
                    else if (message.getAllUsers() != null)
                        peerServer.setAllUsers(message.getAllUsers());
                    else if (message.getContent() != null)
                        peerServer.setGroupNameEncrypted(message.getContent());
                    else
                        peerServer.setUserSearched(message.getReceiver());
                } else {
                    if (!message.getBroadcastMsg()) {
                        String objectKey = "CHATS/" + message.getReceiver().getId() + "/Receive_"
                                + message.getSender().getId() + "_" + message.getTime();
                        peerServer.addMessageToPeer(message);
                        peerServer.uploadCloudPeer(objectKey, message.getContent());
                    } else if (message.getBroadcastMsg()) {
                        // PairingKeySerParameter peerKey = peerServer.getPeerKey();
                        // String groupName = decryptGroupName(message.getFieldName(), peerKey);

                        /*
                         * if (groupName != null) { // Only store the message if this peer was able to
                         * decipher the
                         * // fieldName meaning that the peer has this interest
                         * String objectKey = "CHATS/" + message.getReceiver().getId() + "/Receive_"
                         * + message.getSender().getId() + "_" + groupName + "_" + message.getTime();
                         * Message messageToStore = new Message(message.getSender(),
                         * message.getReceiver(),
                         * message.getContent(), message.getBroadcastMsg(), groupName);
                         * peerServer.addMessageGroupToPeer(messageToStore);
                         * peerServer.uploadCloudPeer(objectKey, message.getContent());
                         * }
                         */
                    }
                }
                break; // Exit after reading the first message (consider removing this break for
                       // continuous listening)
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace(); // Log the error to see what went wrong
        }
    }

    /**
     * Decrypts the group name using the provided peer key.
     * The peer key contains a concatenation of all group keys for the peer's
     * interests.
     * Each segment of the peer key is attempted to decrypt the group name.
     *
     * @param encryptedGroupName The Base64-encoded encrypted group name.
     * @param peerKeyBase64      The Base64-encoded concatenated keys for the peer's
     *                           interests.
     * @return The decrypted group name if successful; null if no key matches.
     */
    /*
     * private String decryptGroupName(String encryptedGroupName, String
     * peerKeyBase64) {
     * try {
     * // Decode the peer key from Base64 to raw bytes
     * byte[] peerKeyBytes = Base64.getDecoder().decode(peerKeyBase64);
     * 
     * int keySize = 32; // Fixed size of an AES-256 key in bytes
     * 
     * // Iterate through the segments of the peer key
     * for (int i = 0; i < peerKeyBytes.length; i += keySize) {
     * byte[] keyPart = Arrays.copyOfRange(peerKeyBytes, i, i + keySize); // Extract
     * each base key
     * Key groupKey = new SecretKeySpec(keyPart, "AES");
     * 
     * try {
     * // Attempt to decrypt the group name with the current key
     * Cipher cipher = Cipher.getInstance("AES");
     * cipher.init(Cipher.DECRYPT_MODE, groupKey);
     * 
     * byte[] decodedBytes = Base64.getDecoder().decode(encryptedGroupName);
     * byte[] decryptedBytes = cipher.doFinal(decodedBytes);
     * 
     * // If decryption is successful, return the group name
     * return new String(decryptedBytes, StandardCharsets.UTF_8);
     * } catch (Exception e) {
     * // Ignore failures and try the next key
     * }
     * }
     * 
     * // If no key successfully decrypts, return null
     * return null;
     * } catch (Exception e) {
     * e.printStackTrace();
     * return null;
     * }
     * }
     */

}
