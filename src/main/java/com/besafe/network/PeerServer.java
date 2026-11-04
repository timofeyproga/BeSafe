package com.besafe.network;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class PeerServer implements AutoCloseable {

    private final ServerSocket serverSocket;

    public PeerServer(int port) throws IOException {
        this.serverSocket = new ServerSocket(port);
    }

    public PeerConnection acceptConnection() throws IOException {
        Socket socket = this.serverSocket.accept();
        return new PeerConnection(socket);
    }

    @Override
    public void close() throws IOException {
        this.serverSocket.close();
    }

}
