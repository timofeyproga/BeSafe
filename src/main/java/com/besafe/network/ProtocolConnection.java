package com.besafe.network;

import com.besafe.protocol.ProtocolMessage;
import com.besafe.protocol.ProtocolSerializer;

import java.io.IOException;

public class ProtocolConnection {

    private final PeerConnection connection;
    private final ProtocolSerializer serializer;

    public ProtocolConnection(PeerConnection connection) {
        if (connection == null) {
            throw new NullPointerException("Connection is null");
        }

        this.connection = connection;
        this.serializer = new ProtocolSerializer();
    }

    public void send(ProtocolMessage message) throws IOException {
        byte[] data = serializer.serialize(message);
        connection.sendBytes(data);
    }

    public ProtocolMessage receive() throws IOException {
        byte[] data = connection.receiveBytes();
        return serializer.deserialize(data);
    }

    public void close() throws IOException {
        connection.close();
    }

}
