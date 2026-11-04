package com.besafe.protocol;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

public class HandshakeTranscript {

    private static final int PROTOCOL_VERSION = 1;

    private final String initiatorId;
    private final String responderId;

    private final PublicKey initiatorKey;
    private final PublicKey responderKey;

    private final byte[] initiatorNonce;
    private final byte[] responderNonce;

    public HandshakeTranscript(
            String initiatorId,
            String responderId,
            PublicKey initiatorKey,
            PublicKey responderKey,
            byte[] initiatorNonce,
            byte[] responderNonce
    ) {
        if (initiatorId == null || initiatorId.isBlank()
        || responderId == null || responderId.isBlank()) {
            throw new IllegalArgumentException("User IDs cannot be null or blank");
        }

        if (initiatorKey == null || responderKey == null) {
            throw new IllegalArgumentException("Public keys cannot be null or blank");
        }

        if (initiatorNonce == null || initiatorNonce.length != 32
        || responderNonce == null || responderNonce.length != 32) {
            throw new  IllegalArgumentException("Nonces must contain 32 bytes");
        }

        this.initiatorId = initiatorId;
        this.responderId = responderId;
        this.initiatorKey = initiatorKey;
        this.responderKey = responderKey;
        this.initiatorNonce = initiatorNonce;
        this.responderNonce = responderNonce;
    }

    public byte[] toByteArray() throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();

        try (DataOutputStream out = new DataOutputStream(byteStream)) {
            out.writeUTF("BeSafe-Handshake");

            out.writeInt(PROTOCOL_VERSION);

            writeString(out, initiatorId);
            writeString(out, responderId);
            writeBytes(out, initiatorKey.getEncoded());
            writeBytes(out, responderKey.getEncoded());
            writeBytes(out, initiatorNonce);
            writeBytes(out, responderNonce);
        }

        return byteStream.toByteArray();

    }

    private void writeString(DataOutputStream out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private void writeBytes(DataOutputStream out, byte[] bytes) throws IOException {
        out.writeInt(bytes.length);
        out.write(bytes);
    }

}
