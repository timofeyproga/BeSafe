package com.besafe.network;

public class PeerAddress {

    private final String host;
    private final int port;

    public PeerAddress(String host, int port) {
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Host cannot be null or blank");
        }

        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Invalid port");
        }

        this.host = host;
        this.port = port;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

}
