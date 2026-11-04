
package com.besafe.protocol;

import com.besafe.identity.UserIdentity;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class HandshakeService {

    private static final int NONCE_LENGTH = 32;
    private static final int SIGNATURE_LENGTH = 64;
    private static final int CHALLENGE_RESPONSE_LENGTH =
            NONCE_LENGTH + SIGNATURE_LENGTH;

    private final UserIdentity localIdentity;
    private final HandshakeState state;
    private final ChallengeService challengeService;
    private final HandshakeCrypto crypto;

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

    // Вызывается инициатором после обмена идентификаторами.
    public ProtocolMessage start() {
        requireRole(HandshakeRole.INITIATOR);
        requireStatus(HandshakeStatus.IDENTITY_EXCHANGED);

        byte[] nonceA = challengeService.generateChallenge();
        state.setInitiatorNonce(nonceA);
        state.setStatus(HandshakeStatus.CHALLENGE_SENT);

        return new ProtocolMessage(MessageType.CHALLENGE, nonceA);
    }

    // Вызывается ответчиком при получении nonceA.
    public ProtocolMessage receiveChallenge(
            ProtocolMessage message
    ) throws GeneralSecurityException, IOException {

        requireRole(HandshakeRole.RESPONDER);
        requireStatus(HandshakeStatus.IDENTITY_EXCHANGED);
        requireMessageType(message, MessageType.CHALLENGE);

        byte[] nonceA = message.getPayload();

        if (nonceA.length != NONCE_LENGTH) {
            fail("Invalid initiator nonce length");
        }

        state.setInitiatorNonce(nonceA);

        byte[] nonceB = challengeService.generateChallenge();
        state.setResponderNonce(nonceB);

        byte[] transcript = createTranscript();
        byte[] signingData = createSigningData(
                "BeSafe-Handshake-Responder-v1",
                transcript
        );

        byte[] signature = crypto.sign(
                signingData,
                localIdentity.getPrivateKey()
        );

        byte[] responsePayload = concatenate(nonceB, signature);

        state.setStatus(HandshakeStatus.RESPONSE_SENT);

        return new ProtocolMessage(
                MessageType.CHALLENGE_RESPONSE,
                responsePayload
        );
    }

    // Вызывается инициатором при получении nonceB и подписи ответчика.
    public ProtocolMessage receiveChallengeResponse(
            ProtocolMessage message
    ) throws GeneralSecurityException, IOException {

        requireRole(HandshakeRole.INITIATOR);
        requireStatus(HandshakeStatus.CHALLENGE_SENT);
        requireMessageType(message, MessageType.CHALLENGE_RESPONSE);

        byte[] payload = message.getPayload();

        if (payload.length != CHALLENGE_RESPONSE_LENGTH) {
            fail("Invalid challenge response length");
        }

        byte[] nonceB = Arrays.copyOfRange(
                payload, 0, NONCE_LENGTH
        );

        byte[] responderSignature = Arrays.copyOfRange(
                payload, NONCE_LENGTH, payload.length
        );

        state.setResponderNonce(nonceB);

        byte[] transcript = createTranscript();
        byte[] responderSigningData = createSigningData(
                "BeSafe-Handshake-Responder-v1",
                transcript
        );

        boolean responderVerified = crypto.verify(
                responderSigningData,
                responderSignature,
                state.getRemoteIdentity().getPublicKey()
        );

        if (!responderVerified) {
            fail("Responder signature verification failed");
        }

        byte[] initiatorSigningData = createSigningData(
                "BeSafe-Handshake-Initiator-v1",
                transcript
        );

        byte[] initiatorSignature = crypto.sign(
                initiatorSigningData,
                localIdentity.getPrivateKey()
        );

        state.setStatus(HandshakeStatus.RESPONSE_SENT);

        return new ProtocolMessage(
                MessageType.AUTHENTICATION_SIGNATURE,
                initiatorSignature
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

        byte[] transcript = createTranscript();
        byte[] signingData = createSigningData(
                "BeSafe-Handshake-Initiator-v1",
                transcript
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

    private byte[] createTranscript() throws IOException {
        if (state.getRemoteIdentity() == null
                || state.getInitiatorNonce() == null
                || state.getResponderNonce() == null) {
            throw new IllegalStateException(
                    "Handshake transcript is incomplete"
            );
        }

        if (state.getRole() == HandshakeRole.INITIATOR) {
            return new HandshakeTranscript(
                    localIdentity.getUserId(),
                    state.getRemoteIdentity().getUserId(),
                    localIdentity.getPublicKey(),
                    state.getRemoteIdentity().getPublicKey(),
                    state.getInitiatorNonce(),
                    state.getResponderNonce()
            ).toByteArray();
        }

        return new HandshakeTranscript(
                state.getRemoteIdentity().getUserId(),
                localIdentity.getUserId(),
                state.getRemoteIdentity().getPublicKey(),
                localIdentity.getPublicKey(),
                state.getInitiatorNonce(),
                state.getResponderNonce()
        ).toByteArray();
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
