package com.besafe.protocol;

public enum MessageType {

    IDENTITY_REQUEST(1),
    IDENTITY_RESPONSE(2),

    CHALLENGE(3),
    CHALLENGE_RESPONSE(4),

    CHAT_MESSAGE(5),
    DISCONNECT(6),

    AUTHENTICATION_FINISH(7),
    AUTHENTICATION_SIGNATURE(8),
    AUTHENTICATION_ACK(9);

    private final int code;

    MessageType(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    public static MessageType fromCode(int code) {
        for (MessageType type : values()) {
            if (type.getCode() == code) {
                return type;
            }
        }

        throw new IllegalArgumentException("Unknown message type code " + code);
    }

}
