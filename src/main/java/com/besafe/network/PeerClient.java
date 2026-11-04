package com.besafe.network;

import java.io.IOException;
import java.net.Socket;

public class PeerClient {

    private final String host;
    private final int port;

    public PeerClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public PeerConnection connect() throws IOException {
        Socket socket = new Socket(host, port);
        return new PeerConnection(socket);
    }

}
