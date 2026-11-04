package com.besafe.protocol;

import java.io.IOException;
import java.net.ProtocolException;
import java.nio.ByteBuffer;

public class ProtocolSerializer {

    private static final int PROTOCOL_VERSION = 1;
    private static final int HEADER_SIZE = 2;

    public static byte[] serialize(ProtocolMessage message) {
        if (message == null) {
            throw new NullPointerException("Message is null");
        }

        byte[] payload = message.getPayload();

        ByteBuffer buffer = ByteBuffer.allocate(HEADER_SIZE + payload.length);

        buffer.put((byte) PROTOCOL_VERSION);
        buffer.put((byte) message.getType().getCode());
        buffer.put(payload);

        return buffer.array();

    }

    public static ProtocolMessage deserialize(byte[] data) throws IOException {
        if (data == null || data.length < HEADER_SIZE) {
            throw new IOException("Invalid protocol message");
        }

        ByteBuffer buffer = ByteBuffer.wrap(data);

        int version = Byte.toUnsignedInt(buffer.get());
        int typeCode = Byte.toUnsignedInt(buffer.get());

        if (version != PROTOCOL_VERSION) {
            throw new IOException("Unsupported protocol version: " + version);
        }

        MessageType type;

        try {
            type = MessageType.fromCode(typeCode);
        } catch (IllegalArgumentException e) {
            throw new IOException("Unknown message type: " + typeCode);
        }

        byte[] payload = new byte[buffer.remaining()];
        buffer.get(payload);

        return new ProtocolMessage(type, payload);
    }

}
