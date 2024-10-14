package com.p2pmessagingapp;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class Peer {
    
    private static SSLSocket sslSocket; // Change from SSLSocket to Socket
    private final static List<User> Users = new ArrayList<>(); // Creates a list of users
    private static String[] values;
    private static PeerServer serverThread;
    private static BufferedReader bufferedReader;


    public static void main(String[] args) throws Exception {
        addShutdownHook(); // Delete client and port files/directories by pressing 'Control + C'

        System.out.println("=> Please enter your id & port below:(Ex: Valeta 6969) ");
        while (true) {
            bufferedReader = new BufferedReader(new InputStreamReader(System.in));
            values = bufferedReader.readLine().split(" "); // Reads and splits user input details
            boolean verificationStatus = fileAndPortVerification(values);
            if (verificationStatus) {
                break;
            }
        }
        serverThread = new PeerServer(values[0], Integer.parseInt(values[1]));
        serverThread.start();

        createUserAtributtes(values[0], Integer.parseInt(values[1]));

        askForcommunication(bufferedReader, values[0], serverThread);
        keepProgramRunning();

    }

    private static void createUserAtributtes(String address, int port) {
        createPortsFile(port);
        createSSLSocket("localhost", port);
        createClientFile(address, port);
        createUser(address, port);
    }

    public Peer(String address, int port) throws Exception {
        createUserAtributtes(address, port);
    }

    public static void createSSLSocket(String address, int port) {
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.2");
            KeyManagerFactory keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keys = KeyStore.getInstance("JKS");
            try (InputStream stream = new FileInputStream("stream.jks")){
                keys.load(stream, "p2pmessagingapp".toCharArray());
            }
            keyManager.init(keys, "p2pmessagingapp".toCharArray());

            KeyStore store = KeyStore.getInstance("JKS");
            try(InputStream storeStream = new FileInputStream("storestream.jks")) {
                store.load(storeStream, "p2pmessagingapp".toCharArray());
            }

            TrustManagerFactory trustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManager.init(store);

            context.init(keyManager.getKeyManagers(), trustManager.getTrustManagers(), null);
            SSLSocketFactory factory = context.getSocketFactory();
            sslSocket = (SSLSocket) factory.createSocket(address, port);
            
        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | 
            UnrecoverableKeyException | CertificateException | KeyManagementException e) {}
    }

    public static void askForcommunication(BufferedReader bufferedReader, String id, PeerServer serverThread) throws Exception {
        
        System.out.println("=> Please enter the ID of the person you want to communicate with below:");
        String otherPeerID;
        User receiverUser = null;
        while(true) {
            otherPeerID = bufferedReader.readLine();
            updateActivePeers();
            receiverUser = findReceiver(otherPeerID);
            if(receiverUser == null) {
                System.out.println("=> Invalid ID, please insert a different ID:");
            }
            else 
                break;
        }

        communicate(bufferedReader, id, serverThread, receiverUser, sslSocket);
    }

    public static void updateActivePeers() {
        File portsFile = new File("Ports");
        try (BufferedReader br = new BufferedReader(new FileReader(portsFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                int port = Integer.parseInt(line);
                
                File folder = new File("clients");
                String user = null;
                if (folder.exists() && folder.isDirectory()) {
                    File[] files = folder.listFiles(); // Iterate through the files
                    if (files != null) {
                        for (File file : files) {
                            if (file.isFile()) {
                                try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                                    String filePort = reader.readLine();
                                    if(Integer.parseInt(filePort) == port) {
                                        user = file.getName();
                                    }
                                } catch (IOException e) {}
                            }
                        }
                    }
                }
                createUser(user, port); 
            }
        } catch (IOException e) {}
    }

    public static void communicate(BufferedReader bufferedReader, String id, PeerServer serverThread, User receiver, SSLSocket sslSocket) {
        try {
            System.out.println("You can now communicate (e to exit, c to change)");
            OUTER:
            while (true) {
                String content = bufferedReader.readLine();
                switch (content) {
                    case "e":
                        // exit the communication
                        deleteClientFile(values[0]);
                        deletePortLine();
                        break OUTER;
                    case "c":
                        // change the peer
                        askForcommunication(bufferedReader, id, serverThread);
                        break;
                    default:
                        Message message = new Message(Users.get(0), receiver, content);
                        serverThread.sendMessage(message);
                        break;
                }
            }
            Peer.main(values);
        } catch (Exception e) {}
    }

    public void sendMessage(byte[] serializedMessage) {
        try (OutputStream outputStream = sslSocket.getOutputStream()) {
            // Enviar a mensagem (os bytes) através do OutputStream
            System.out.println("Vamos enviar para porta: "+sslSocket.getPort());
            outputStream.write(serializedMessage);
            System.out.println("puta");
            outputStream.flush();
        } catch (IOException e) {}
    }

    private static void createClientFile(String id, int port) {
        try {
            File dir = new File("clients");
            if (!dir.exists()) {
                dir.mkdir(); // Create the directory if it does not exist
            }

            File file = new File(dir, id);
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                writer.write(String.valueOf(port)); // write the port in the file
            } // write the port in the file

        } catch (IOException e) {}
    }

    private static void deleteClientFile(String userId) {
        File dir = new File("clients");

        if (dir.exists() && dir.isDirectory()) {
            File userFile = new File(dir, userId);
            
            if (userFile.exists()) {
                if (userFile.delete()) {
                    System.out.println("File for user '" + userId + "' deleted successfully.");
                
                    if (dir.list().length == 0) {
                        if (dir.delete()) System.out.println("Directory 'clients' deleted successfully");
                        else System.out.println("Failed to delete directory 'clients'.");
                    } else System.out.println("Directory 'clients' is not empty.");
                } else System.out.println("Failed to delete file for user '" + userId + "'.");
            } else System.out.println("File for user '" + userId + "' does not exist.");
        } else System.out.println("Directory 'clients' does not exist.");
    }

    private static void createPortsFile(int port) {
        boolean alreadyExists = false;
        for(User user: Users) {
            if (user.getPort() == port) alreadyExists = true;
        }
        File portFile;
        if(!alreadyExists) {
            try {
                portFile = new File("Ports");
                portFile.createNewFile();
                BufferedWriter writer;
                try (Scanner sc = new Scanner(portFile)) {
                    writer = new BufferedWriter(new FileWriter(portFile, true)); // append mode
                    while (sc.hasNextLine()) {
                        sc.nextLine();
                    }
                } // append mode
                writer.write(String.valueOf(port)); // write the port in the file
                writer.write(System.getProperty("line.separator"));
                writer.close();
    
            } catch (IOException e) {}
        }
    }

    private static void deletePortsFile() {
        File portsFile = new File("Ports");

        // Verifica se o arquivo existe
        if (portsFile.exists()) {
            if (portsFile.delete()) {
                System.out.println("File 'Ports' deleted successfully.");
            } else {
                System.out.println("Failed to delete file 'Ports'.");
            }
        } else {
            System.out.println("File 'Ports' does not exist.");
        }
    }

    private static void deletePortLine() throws IOException {
        File portsFile = new File("Ports");

        try (BufferedReader reader = new BufferedReader(new FileReader(portsFile))) {
            String line;
            StringBuilder contents = new StringBuilder();

            while ((line = reader.readLine()) != null) {
                if (line.equals(values[1])) {
                    continue;
                }
                contents.append(line).append(System.lineSeparator());
            }
            reader.close();

            try (BufferedWriter writer = new BufferedWriter(new FileWriter(portsFile))) {
                writer.write(contents.toString());
                writer.close();
            }
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(portsFile))) {
            if(reader.readLine() == null) {
                reader.close();
                deletePortsFile();
            }
        }
    }

    private static boolean fileAndPortVerification(String[] values) {
        // Check if the correct number of values was provided
        if (values.length != 2) {
            System.out.println("=> error: input must be in the format 'id port' (e.g., Valeta 6969).");
            return false;
        }
    
        String errorMessage = "";
        File filename = new File("clients/" + values[0]); // Check if the ID already exists
        if (filename.exists()) errorMessage = "ID";
    
        // Check if the second value (port) is a valid number
        try {
            int port = Integer.parseInt(values[1]);
            if (port <= 0 || port > 65535) { // Limit the port to a range between 1 and 65535
                System.out.println("=> error: port must be a number between 1 and 65535.");
                return false;
            }
        } catch (NumberFormatException e) {
            System.out.println("=> error: port must be a valid number.");
            return false;
        }
    
        // Check if the port is already in use
        File folder = new File("clients");
        if (folder.exists() && folder.isDirectory()) {
            File[] files = folder.listFiles(); // Iterate through the files
            if (files != null) {
                for (File file : files) {
                    if (file.isFile()) {
                        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                            String filePort = reader.readLine(); // Read the file content (port)
                            if (filePort.equals(values[1])) { // Check if the port already exists
                                if (errorMessage.equals("")) errorMessage = "Port";
                                else errorMessage = "ID and Port";
                            }
                            reader.close();
                        } catch (IOException e) {}
                    }
                }
            }
        }
    
        if (errorMessage.equals("")) return true;
        System.out.println("=> " + errorMessage + " already in use, please insert a different " + errorMessage + ":");
        return false;
    }

    private static void createUser(String id, int port) {
        boolean canCreateUser = true;
        for (User user : Users) {
            if (user.getId().equals(id)) { // Verifica se o id do usuário corresponde ao id passado como argumento
                canCreateUser =  false; // Retorna o usuário encontrado
            }
        }
        if(canCreateUser) {
            User user = new User(id, port);
            Users.add(user);
        }
    }

    private static User findReceiver(String id) {
        for (User user : Users) {
            try {
                if (user.getId().equals(id) && !user.getId().equals(Users.get(0).getId())) { // Verifica se o id do usuário corresponde ao id passado como argumento
                    return user; // Retorna o usuário encontrado
                }
            } catch (NullPointerException e) {
                return null;
            }
        }
        return null;
    }

    // Método para adicionar o shutdown hook
    private static void addShutdownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutdown hook triggered.");
            try {
                deleteClientFile(values[0]);
                deletePortLine(); // Passa a porta atual do cliente
            } catch (IOException e) {}
        }));
    }

    // Método para manter o programa em execução
    private static void keepProgramRunning() {
        try {
            Thread.sleep(Long.MAX_VALUE);
        }catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.out.println("Program interrupted.");
            System.exit(0);
        }
    }


}
