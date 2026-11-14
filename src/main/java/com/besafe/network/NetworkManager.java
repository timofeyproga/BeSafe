package com.besafe.network;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class NetworkManager implements AutoCloseable {

    private final MessageHandler messageHandler;

    private final ConcurrentMap<PeerConnection, PeerListener> listeners =
            new ConcurrentHashMap<>();

    private final Object lifecycleLock = new Object();

    private PeerServer server;
    private Thread acceptThread;

    private volatile boolean serverRunning;
    private boolean closed;

    public NetworkManager(MessageHandler messageHandler) {
        if (messageHandler == null) {
            throw new IllegalArgumentException("MessageHandler cannot be null");
        }

        this.messageHandler = messageHandler;
    }

    public void startServer(int port) throws IOException {
        synchronized (lifecycleLock) {
            ensureOpen();

            if (server != null) {
                throw new IllegalStateException("Server is already running");
            }

            server = new PeerServer(port);
            serverRunning = true;

            PeerServer activeServer = server;

            acceptThread = new Thread(
                    () -> acceptLoop(activeServer),
                    "BeSafe-AcceptThread"
            );

            acceptThread.setDaemon(true);
            acceptThread.start();
        }
    }

    private void acceptLoop(PeerServer activeServer) {
        try {
            while (serverRunning && server == activeServer) {
                PeerConnection connection = activeServer.acceptConnection();

                synchronized (lifecycleLock) {
                    if (!serverRunning || server != activeServer || closed) {
                        connection.close();
                        break;
                    }

                    registerConnection(connection);
                }
            }

        } catch (IOException e) {
            if (serverRunning && server == activeServer) {
                e.printStackTrace();
            }

        } finally {
            synchronized (lifecycleLock) {
                if (server == activeServer) {
                    server = null;
                    serverRunning = false;
                    acceptThread = null;
                }
            }

            try {
                activeServer.close();
            } catch (IOException ignored) {
            }
        }
    }

    public PeerConnection connect(String host, int port) throws IOException {
        synchronized (lifecycleLock) {
            ensureOpen();
        }

        PeerClient client = new PeerClient(host, port);
        PeerConnection connection = client.connect();

        try {
            registerConnection(connection);
        } catch (IOException | RuntimeException e) {
            try {
                connection.close();
            } catch (IOException closeException) {
                e.addSuppressed(closeException);
            }

            throw e;
        }

        return connection;
    }

    private void registerConnection(PeerConnection connection) throws IOException {
        synchronized (lifecycleLock) {
            ensureOpen();

            MessageHandler connectionHandler = new MessageHandler() {

                @Override
                public void onMessageReceived(
                        PeerConnection source,
                        byte[] message
                ) {
                    messageHandler.onMessageReceived(source, message);
                }

                @Override
                public void onDisconnected(PeerConnection source) {
                    listeners.remove(source);
                    messageHandler.onDisconnected(source);
                }
            };

            PeerListener listener = new PeerListener(
                    connection,
                    connectionHandler
            );

            if (listeners.putIfAbsent(connection, listener) != null) {
                throw new IOException("Connection is already registered");
            }

            listener.start();
        }
    }

    public Set<PeerConnection> getConnections() {
        return Set.copyOf(listeners.keySet());
    }

    public void disconnect(PeerConnection connection) {
        if (connection == null) {
            return;
        }

        PeerListener listener = listeners.remove(connection);

        if (listener != null) {
            listener.stop();
        } else {
            try {
                connection.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void stopServer() {
        PeerServer activeServer;

        synchronized (lifecycleLock) {
            activeServer = server;

            server = null;
            serverRunning = false;
            acceptThread = null;
        }

        if (activeServer != null) {
            try {
                activeServer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public boolean isServerRunning() {
        return serverRunning;
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("NetworkManager is closed");
        }
    }

    @Override
    public void close() {
        PeerServer activeServer;
        Map<PeerConnection, PeerListener> activeListeners;

        synchronized (lifecycleLock) {
            if (closed) {
                return;
            }

            closed = true;
            serverRunning = false;

            activeServer = server;
            server = null;
            acceptThread = null;

            activeListeners = Map.copyOf(listeners);
            listeners.clear();
        }

        if (activeServer != null) {
            try {
                activeServer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        for (PeerListener listener : activeListeners.values()) {
            listener.stop();
        }
    }
}