package com.besafe.network;

import java.io.EOFException;
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

    public synchronized void start() {
        if (running) {
            return;
        }

        running = true;

        connectionThread = new Thread(() -> {
            try {
                while (running) {
                    byte[] message = connection.receiveBytes();

                    messageHandler.onMessageReceived(connection, message);
                }
            } catch (EOFException ignored) {

            } catch (IOException e) {
                if (running) {
                    e.printStackTrace();
                }
            } finally {
                running = false;
                messageHandler.onDisconnected(connection);
            }
        }, "BeSafe-PeerListener");

        connectionThread.setDaemon(true);
        connectionThread.start();
    }

    public void stop() {
        running = false;

        try {
            connection.close();
        } catch (IOException ignored) {
        }

        if (connectionThread != null) {
            connectionThread.interrupt();
        }
    }

    public boolean isRunning() {
        return running;
    }
}
