package com.besafe.protocol;

public class ProtocolMessage {

    private final MessageType type;
    private final byte[] payload;

    public ProtocolMessage(MessageType type, byte[] payload) {
        if (type == null) {
            throw new IllegalArgumentException("Type cannot be null");
        }

        if  (payload == null) {
            throw new IllegalArgumentException("Payload cannot be null");
        }

        this.type = type;
        this.payload = payload.clone();
    }

    public MessageType getType() {
        return type;
    }

    public byte[] getPayload() {
        return payload.clone();
    }

}
