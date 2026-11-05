package com.besafe.protocol;

import com.besafe.crypto.KeyExchange;
import com.besafe.identity.UserIdentity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;

public class HandshakeService {

    private static final int NONCE_LENGTH = 32;
    private static final int SIGNATURE_LENGTH = 64;

    private final UserIdentity localIdentity;
    private final HandshakeState state;
    private final ChallengeService challengeService;
    private final HandshakeCrypto crypto;

    private KeyExchange keyExchange = new KeyExchange();
    private SecureRandom secureRandom = new SecureRandom();

    public HandshakeService(
            UserIdentity localIdentity,
            HandshakeState state,
            ChallengeService challengeService,
            HandshakeCrypto crypto
    ) {
        if (localIdentity == null || state == null
                || challengeService == null || crypto == null) {
            throw new IllegalArgumentException(
                    "Handshake dependencies cannot be null"
            );
        }

        this.localIdentity = localIdentity;
        this.state = state;
        this.challengeService = challengeService;
        this.crypto = crypto;
    }

    public ProtocolMessage start() throws GeneralSecurityException, IOException {
        requireRole(HandshakeRole.INITIATOR);
        requireStatus(HandshakeStatus.IDENTITY_EXCHANGED);

        byte[] nonceA = generateNonce();

        KeyPair ephemeralKeyPair = keyExchange.generateKeyPair();

        state.setInitiatorNonce(nonceA);
        state.setLocalEphemeralKeyPair(ephemeralKeyPair);

        byte[] payload = serializeChallengePayload(
                nonceA,
                ephemeralKeyPair.getPublic().getEncoded()
        );

        state.setStatus(HandshakeStatus.CHALLENGE_SENT);

        return new ProtocolMessage(MessageType.CHALLENGE, payload);
    }

    public ProtocolMessage receiveChallenge(ProtocolMessage message)
            throws GeneralSecurityException, IOException {

        requireRole(HandshakeRole.RESPONDER);
        requireStatus(HandshakeStatus.IDENTITY_EXCHANGED);
        requireMessageType(message, MessageType.CHALLENGE);

        ChallengePayload challenge = deserializeChallengePayload(message.getPayload());

        state.setInitiatorNonce(challenge.nonce());
        state.setRemoteEphemeralPublicKey(
                keyExchange.decodePublicKey(challenge.ephemeralPublicKey())
        );

        KeyPair ephemeralKeyPair = keyExchange.generateKeyPair();
        byte[] nonceB = generateNonce();

        state.setResponderNonce(nonceB);
        state.setLocalEphemeralKeyPair(ephemeralKeyPair);

        HandshakeTranscript transcript = createTranscript();

        byte[] signingData = createSigningData(
                "BeSafe-Handshake-Responder-v1",
                transcript.toByteArray()
        );

        byte[] signature = crypto.sign(
                signingData,
                localIdentity.getPrivateKey()
        );

        byte[] payload = serializeChallengeResponsePayload(
                nonceB,
                ephemeralKeyPair.getPublic().getEncoded(),
                signature
        );

        state.setStatus(HandshakeStatus.RESPONSE_SENT);

        return new ProtocolMessage(MessageType.CHALLENGE_RESPONSE, payload);
    }

    public ProtocolMessage receiveChallengeResponse(ProtocolMessage message)
            throws GeneralSecurityException, IOException {

        requireRole(HandshakeRole.INITIATOR);
        requireStatus(HandshakeStatus.CHALLENGE_SENT);
        requireMessageType(message, MessageType.CHALLENGE_RESPONSE);

        ChallengeResponsePayload response =
                deserializeChallengeResponsePayload(message.getPayload());

        state.setResponderNonce(response.nonce());
        state.setRemoteEphemeralPublicKey(
                keyExchange.decodePublicKey(response.ephemeralPublicKey())
        );

        HandshakeTranscript transcript = createTranscript();

        byte[] signingData = createSigningData(
                "BeSafe-Handshake-Responder-v1",
                transcript.toByteArray()
        );

        boolean valid = crypto.verify(
                signingData,
                response.signature(),
                state.getRemoteIdentity().getPublicKey()
        );

        if (!valid) {
            fail("Invalid responder signature");
            throw new SecurityException("Invalid responder signature");
        }

        byte[] initiatorSigningData = createSigningData(
                "BeSafe-Handshake-Initiator-v1",
                transcript.toByteArray()
        );

        byte[] signature = crypto.sign(
                initiatorSigningData,
                localIdentity.getPrivateKey()
        );

        state.setStatus(HandshakeStatus.RESPONSE_SENT);

        return new ProtocolMessage(
                MessageType.AUTHENTICATION_SIGNATURE,
                signature
        );
    }

    // Вызывается ответчиком при получении подписи инициатора.
    public ProtocolMessage receiveAuthenticationSignature(
            ProtocolMessage message
    ) throws GeneralSecurityException, IOException {

        requireRole(HandshakeRole.RESPONDER);
        requireStatus(HandshakeStatus.RESPONSE_SENT);
        requireMessageType(
                message,
                MessageType.AUTHENTICATION_SIGNATURE
        );

        byte[] signature = message.getPayload();

        if (signature.length != SIGNATURE_LENGTH) {
            fail("Invalid authentication signature length");
        }

        HandshakeTranscript transcript = createTranscript();

        byte[] signingData = createSigningData(
                "BeSafe-Handshake-Initiator-v1",
                transcript.toByteArray()
        );

        boolean initiatorVerified = crypto.verify(
                signingData,
                signature,
                state.getRemoteIdentity().getPublicKey()
        );

        if (!initiatorVerified) {
            fail("Initiator signature verification failed");
        }

        state.setStatus(HandshakeStatus.AUTHENTICATED);

        return new ProtocolMessage(
                MessageType.AUTHENTICATION_FINISH,
                new byte[0]
        );
    }

    // Вызывается инициатором при получении финального подтверждения.
    public void receiveAuthenticationFinish(
            ProtocolMessage message
    ) {
        requireRole(HandshakeRole.INITIATOR);
        requireStatus(HandshakeStatus.RESPONSE_SENT);
        requireMessageType(
                message,
                MessageType.AUTHENTICATION_FINISH
        );

        if (message.getPayload().length != 0) {
            fail("Authentication finish must have an empty payload");
        }

        state.setStatus(HandshakeStatus.AUTHENTICATED);
    }

    private HandshakeTranscript createTranscript() {
        IdentityPayload remote = state.getRemoteIdentity();

        if (state.getRole() == HandshakeRole.INITIATOR) {
            return new HandshakeTranscript(
                    localIdentity.getUserId(),
                    remote.getUserId(),
                    localIdentity.getPublicKey(),
                    remote.getPublicKey(),
                    state.getInitiatorNonce(),
                    state.getResponderNonce(),
                    state.getLocalEphemeralKeyPair().getPublic(),
                    state.getRemoteEphemeralPublicKey()
            );
        }

        return new HandshakeTranscript(
                remote.getUserId(),
                localIdentity.getUserId(),
                remote.getPublicKey(),
                localIdentity.getPublicKey(),
                state.getInitiatorNonce(),
                state.getResponderNonce(),
                state.getRemoteEphemeralPublicKey(),
                state.getLocalEphemeralKeyPair().getPublic()
        );
    }

    private byte[] createSigningData(
            String context,
            byte[] transcript
    ) throws IOException {

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        try (DataOutputStream output = new DataOutputStream(buffer)) {
            output.writeUTF(context);
            output.writeInt(transcript.length);
            output.write(transcript);
        }

        return buffer.toByteArray();
    }

    private byte[] concatenate(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(
                first,
                first.length + second.length
        );

        System.arraycopy(
                second, 0,
                result, first.length,
                second.length
        );

        return result;
    }

    private byte[] serializeChallengePayload(byte[] nonce, byte[] publicKey)
            throws IOException {

        validatePayloadParts(nonce, publicKey);

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(buffer);

        output.write(nonce);
        output.writeInt(publicKey.length);
        output.write(publicKey);

        return buffer.toByteArray();
    }

    private ChallengePayload deserializeChallengePayload(byte[] payload)
            throws IOException {

        DataInputStream input = new DataInputStream(
                new ByteArrayInputStream(payload)
        );

        byte[] nonce = new byte[NONCE_LENGTH];
        input.readFully(nonce);

        int keyLength = input.readInt();

        if (keyLength <= 0 || keyLength > 128) {
            throw new IOException("Invalid ephemeral public key length");
        }

        byte[] publicKey = new byte[keyLength];
        input.readFully(publicKey);

        if (input.available() != 0) {
            throw new IOException("Unexpected trailing data in CHALLENGE");
        }

        return new ChallengePayload(nonce, publicKey);
    }

    private byte[] serializeChallengeResponsePayload(
            byte[] nonce,
            byte[] publicKey,
            byte[] signature
    ) throws IOException {

        validatePayloadParts(nonce, publicKey);

        if (signature == null || signature.length != SIGNATURE_LENGTH) {
            throw new IllegalArgumentException("Invalid signature length");
        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(buffer);

        output.write(nonce);
        output.writeInt(publicKey.length);
        output.write(publicKey);
        output.write(signature);

        return buffer.toByteArray();
    }

    private ChallengeResponsePayload deserializeChallengeResponsePayload(
            byte[] payload
    ) throws IOException {

        DataInputStream input = new DataInputStream(
                new ByteArrayInputStream(payload)
        );

        byte[] nonce = new byte[NONCE_LENGTH];
        input.readFully(nonce);

        int keyLength = input.readInt();

        if (keyLength <= 0 || keyLength > 128) {
            throw new IOException("Invalid ephemeral public key length");
        }

        byte[] publicKey = new byte[keyLength];
        input.readFully(publicKey);

        byte[] signature = new byte[SIGNATURE_LENGTH];
        input.readFully(signature);

        if (input.available() != 0) {
            throw new IOException("Unexpected trailing data in CHALLENGE_RESPONSE");
        }

        return new ChallengeResponsePayload(nonce, publicKey, signature);
    }

    private void validatePayloadParts(byte[] nonce, byte[] publicKey) {
        if (nonce == null || nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException("Invalid nonce");
        }

        if (publicKey == null || publicKey.length == 0 || publicKey.length > 128) {
            throw new IllegalArgumentException("Invalid public key");
        }
    }

    private record ChallengePayload(byte[] nonce, byte[] ephemeralPublicKey) {}

    private record ChallengeResponsePayload(
            byte[] nonce,
            byte[] ephemeralPublicKey,
            byte[] signature
    ) {}

    private byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_LENGTH];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    private void requireRole(HandshakeRole expected) {
        if (state.getRole() != expected) {
            fail("Invalid handshake role");
        }
    }

    private void requireStatus(HandshakeStatus expected) {
        if (state.getStatus() != expected) {
            fail("Invalid handshake status: " + state.getStatus());
        }
    }

    private void requireMessageType(
            ProtocolMessage message,
            MessageType expected
    ) {
        if (message == null || message.getType() != expected) {
            fail("Unexpected protocol message");
        }
    }

    private void fail(String reason) {
        state.setStatus(HandshakeStatus.FAILED);
        throw new IllegalStateException(reason);
    }
}
