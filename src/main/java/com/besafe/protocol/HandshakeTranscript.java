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

    private final PublicKey initiatorEphemeralKey;
    private final PublicKey responderEphemeralKey;

    public HandshakeTranscript(
            String initiatorId,
            String responderId,
            PublicKey initiatorKey,
            PublicKey responderKey,
            byte[] initiatorNonce,
            byte[] responderNonce,
            PublicKey initiatorEphemeralKey,
            PublicKey responderEphemeralKey
    ) {
        if (initiatorId == null || initiatorId.isBlank()
        || responderId == null || responderId.isBlank()) {
            throw new IllegalArgumentException("User IDs cannot be null or blank");
        }

        if (initiatorKey == null || responderKey == null) {
            throw new IllegalArgumentException("Public keys cannot be null or blank");
        }

        validateEphemeralKey(initiatorEphemeralKey);
        validateEphemeralKey(responderEphemeralKey);

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
        this.initiatorEphemeralKey = initiatorEphemeralKey;
        this.responderEphemeralKey = responderEphemeralKey;
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

            writeBytes(out, initiatorEphemeralKey.getEncoded());
            writeBytes(out, responderEphemeralKey.getEncoded());
        }

        return byteStream.toByteArray();

    }

    private void writeString(DataOutputStream out, String value) throws IOException {
        if (value == null) {
            throw new IllegalArgumentException("Value cannot be null");
        }

        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private void writeBytes(DataOutputStream out, byte[] bytes) throws IOException {
        if (bytes == null) {
            throw new IllegalArgumentException("Bytes cannot be null");
        }

        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private void validateEphemeralKey(PublicKey key) {
        if (key == null) {
            throw new IllegalArgumentException("Ephemeral public key cannot be null");
        }

        String algorithm = key.getAlgorithm();

        if (!algorithm.equalsIgnoreCase("X25519")
              && !algorithm.equalsIgnoreCase("XDH")) {
            throw new IllegalArgumentException("Only X25519 keys are supported");
        }

        if (key.getEncoded() == null) {
            throw new IllegalArgumentException("Ephemeral public key has no encoded registration");
        }
    }

}
