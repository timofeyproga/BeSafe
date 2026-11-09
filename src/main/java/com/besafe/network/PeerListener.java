package com.besafe.network;

import java.io.IOException;

public class PeerListener {

    private final MessageHandler messageHandler;
    private final PeerConnection connection;

    private Thread connectionThread;
    private volatile boolean running;

    public PeerListener(PeerConnection connection, MessageHandler messageHandler) {
        this.connection = connection;
        this.messageHandler = messageHandler;
    }

    public void start() {
        if (running) {
            return;
        }

        running = true;

        connectionThread = new Thread(() -> {
            while (running) {
                try {
                    byte[] message = connection.receiveBytes();

                    if (message == null) {
                        running = false;
                        return;
                    }

                    messageHandler.onMessageReceived(connection, message);
                } catch (IOException e) {
                    if (running) {
                        e.printStackTrace();
                    }

                    running = false;
                    break;
                }
            }
        }, "BeSafe-PeerListener");

        connectionThread.setDaemon(true);
        connectionThread.start();
    }

    public void stop() {
        if (!running) {
            return;
        }

        running = false;
        try {
            connection.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
