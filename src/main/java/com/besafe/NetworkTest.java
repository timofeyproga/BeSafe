package com.besafe;

import com.besafe.network.PeerClient;
import com.besafe.network.PeerConnection;
import com.besafe.network.PeerServer;

import java.io.EOFException;
import java.io.IOException;

public class NetworkTest {

    public static void main(String[] args) {
        Thread serverThread = new Thread(() -> {
            try (PeerServer server = new PeerServer(5050)) {

                System.out.println("Server started on port 5050");

                PeerConnection connection = server.acceptConnection();

                System.out.println("Client connected!");

                try (connection) {
                    while (true) {
                        try {
                            String message = connection.receiveMessage();

                            System.out.println("[SERVER] " + message);

                            connection.sendMessage(
                                    "Message received by server!"
                            );
                        } catch (EOFException e) {
                            System.out.println("Client disconnected!");
                            break;
                        }
                    }
                }

            } catch (IOException e) {
                e.printStackTrace();
            }
        });

        serverThread.start();

        try {
            Thread.sleep(500);

            PeerClient client = new PeerClient("127.0.0.1", 5050);

            try (PeerConnection connection = client.connect()) {
                System.out.println("Connected to server!");

                connection.sendMessage("Hello from client!");

                String response = connection.receiveMessage();

                System.out.println("[CLIENT] " + response);
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

}
