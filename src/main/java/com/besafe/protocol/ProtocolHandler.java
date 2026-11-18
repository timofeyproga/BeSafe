package com.besafe.protocol;

import com.besafe.crypto.MessageCipher;
import com.besafe.identity.UserIdentity;
import com.besafe.network.MessageHandler;
import com.besafe.network.PeerConnection;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ProtocolHandler implements MessageHandler {

    private static final String TRUST_ACCEPT_PAYLOAD =
            "BeSafe-Trust-v1:ACCEPT";

    private static final String TRUST_REJECT_PAYLOAD =
            "BeSafe-Trust-v1:REJECT";

    private final UserIdentity localIdentity;
    private final ProtocolEvents events;

    private final Map<PeerConnection, ConnectionContext> connections =
            new ConcurrentHashMap<>();

    private final MessageCipher messageCipher = new MessageCipher();

    public ProtocolHandler(UserIdentity localIdentity) {
        this(localIdentity, new ProtocolEvents() {});
    }

    public ProtocolHandler(
            UserIdentity localIdentity,
            ProtocolEvents events
    ) {
        if (localIdentity == null) {
            throw new IllegalArgumentException("Local identity cannot be null");
        }

        if (events == null) {
            throw new IllegalArgumentException("ProtocolEvents cannot be null");
        }

        this.localIdentity = localIdentity;
        this.events = events;
    }

    public void startIdentityExchange(PeerConnection connection) throws IOException {
        if (connection == null) {
            throw new NullPointerException("Connection is null");
        }

        ConnectionContext context =
                new ConnectionContext(new HandshakeState(HandshakeRole.INITIATOR), true);

        if (connections.putIfAbsent(connection, context) != null) {
            throw new IllegalStateException("Identity exchange already started for this connection");
        }

        try {
            IdentityPayload identity = createLocalIdentityPayload();

            ProtocolMessage request = new ProtocolMessage(
                    MessageType.IDENTITY_REQUEST,
                    IdentityPayloadSerializer.serialize(identity)
            );

            send(connection, request);
        } catch (IOException | RuntimeException e) {
            connections.remove(connection);
            throw e;
        }
    }

    @Override
    public void onMessageReceived(PeerConnection connection, byte[] data) {
        try {
            ProtocolMessage message = ProtocolSerializer.deserialize(data);

            switch (message.getType()) {

                case IDENTITY_REQUEST ->
                    handleIdentityRequest(connection, message);

                case IDENTITY_RESPONSE ->
                    handleIdentityResponse(connection, message);

                case CHALLENGE ->
                    handleChallenge(connection, message);

                case CHALLENGE_RESPONSE ->
                    handleChallengeResponse(connection, message);

                case AUTHENTICATION_SIGNATURE ->
                    handleAuthenticationSignature(connection, message);

                case AUTHENTICATION_FINISH ->
                    handleAuthenticationFinish(connection, message);

                case AUTHENTICATION_ACK ->
                    handleAuthenticationAck(connection, message);

                case DISCONNECT -> {
                    connections.remove(connection);
                    events.onDisconnected(connection);
                    connection.close();
                }

                case CHAT_MESSAGE ->
                    handleChatMessage(connection, message);

                case TRUST_ACCEPT ->
                    handleTrustAccept(connection, message);

                case TRUST_REJECT ->
                    handleTrustReject(connection, message);

                default ->
                    throw new IOException("Unsupported protocol message: " + message.getType());

            }
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            failConnection(connection, e);
        }
    }

    public void sendChatMessage(
            PeerConnection connection,
            String text
    ) throws IOException, GeneralSecurityException {

        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("Message text cannot be null or blank");
        }

        ConnectionContext context = getContext(connection);

        synchronized (context) {
            if (context.state.getStatus() != HandshakeStatus.AUTHENTICATED) {
                throw new IOException("Connection is not authenticated");
            }

            if (!isMutuallyTrusted(context)) {
                throw new IOException("Cannot send messages before mutual trust is established");
            }

            byte[] key = getOutboundKey(context);
            byte[] plaintext = text.getBytes(StandardCharsets.UTF_8);

            try {
                byte[] encrypted = messageCipher.encrypt(plaintext, key);

                ProtocolMessage message = new ProtocolMessage(
                        MessageType.CHAT_MESSAGE,
                        encrypted
                );

                send(connection, message);
            } finally {
                Arrays.fill(key, (byte) 0);
                Arrays.fill(plaintext, (byte) 0);
            }
        }

    }

    private void handleIdentityRequest(
            PeerConnection connection,
            ProtocolMessage message
    ) throws IOException {
        if (connections.containsKey(connection)) {
            throw new IOException("Unexpected identity request");
        }

        IdentityPayload remoteIdentity =
                IdentityPayloadSerializer.deserialize(message.getPayload());

        HandshakeState state = new HandshakeState(HandshakeRole.RESPONDER);

        state.setRemoteIdentity(remoteIdentity);
        state.setStatus(HandshakeStatus.IDENTITY_EXCHANGED);

        ConnectionContext context = new ConnectionContext(state, false);

        context.handshakeService = createHandshakeService(state);

        if (connections.putIfAbsent(connection, context) != null) {
            throw new IOException("Connection context already exists");
        }

        IdentityPayload localIdentityPayload = createLocalIdentityPayload();

        ProtocolMessage response = new ProtocolMessage(
                MessageType.IDENTITY_RESPONSE,
                IdentityPayloadSerializer.serialize(localIdentityPayload)
        );

        send(connection, response);
    }

    private void handleIdentityResponse(
            PeerConnection connection,
            ProtocolMessage message
    ) throws IOException, GeneralSecurityException {

        ConnectionContext context = getContext(connection);

        if (!context.initiator || context.handshakeService != null) {
            throw new IOException("Unexpected identity response");
        }

        IdentityPayload remoteIdentity = IdentityPayloadSerializer.deserialize(message.getPayload());

        context.state.setRemoteIdentity(remoteIdentity);
        context.state.setStatus(HandshakeStatus.IDENTITY_EXCHANGED);

        context.handshakeService = createHandshakeService(context.state);

        ProtocolMessage challenge = context.handshakeService.start();

        send(connection, challenge);
    }

    private void handleChallenge(
            PeerConnection connection,
            ProtocolMessage message
    ) throws IOException, GeneralSecurityException {

        ConnectionContext context = getContext(connection);

        if (context.initiator) {
            throw new IOException("Initiator cannot receive CHALLENGE");
        }

        ProtocolMessage response = context.handshakeService.receiveChallenge(message);

        send(connection, response);
    }

    private void handleChallengeResponse(
            PeerConnection connection,
            ProtocolMessage message
    ) throws IOException, GeneralSecurityException {

        ConnectionContext context = getContext(connection);

        if (!context.initiator) {
            throw new IOException("Responder cannot receive CHALLENGE_RESPONSE");
        }

        ProtocolMessage response = context.handshakeService.receiveChallengeResponse(message);

        send(connection, response);
    }

    private void handleAuthenticationSignature(
            PeerConnection connection,
            ProtocolMessage message
    ) throws IOException, GeneralSecurityException {

        ConnectionContext context = getContext(connection);

        if (context.initiator) {
            throw new IOException("Initiator cannot receive its own signature");
        }

        ProtocolMessage finish = context.handshakeService.receiveAuthenticationSignature(message);

        send(connection, finish);
    }

    private void handleAuthenticationFinish(
            PeerConnection connection,
            ProtocolMessage message
    ) throws IOException, GeneralSecurityException {

        ConnectionContext context = getContext(connection);

        if (!context.initiator) {
            throw new IOException("Responder cannot receive AUTHENTICATION_FINISH");
        }

        ProtocolMessage ack = context.handshakeService.receiveAuthenticationFinish(message);

        send(connection, ack);

        context.handshakeService.markAuthenticationAckSent();

        events.onAuthenticated(
                connection,
                context.state.getRemoteIdentity()
        );
    }

    private void handleAuthenticationAck(
            PeerConnection connection,
            ProtocolMessage message
    ) throws IOException, GeneralSecurityException {

        ConnectionContext context = getContext(connection);

        if (context.initiator) {
            throw new IOException("Initiator cannot receive AUTHENTICATION_ACK");
        }

        context.handshakeService.receiveAuthenticationAck(message);
        events.onAuthenticated(
                connection,
                context.state.getRemoteIdentity()
        );
    }

    private void handleChatMessage(
            PeerConnection connection,
            ProtocolMessage message
    ) throws IOException, GeneralSecurityException {

        ConnectionContext context = getContext(connection);

        String text;

        synchronized (context) {
            if (context.state.getStatus() != HandshakeStatus.AUTHENTICATED) {
                throw new IOException("Received message before authentication");
            }

            if (!isMutuallyTrusted(context)) {
                throw new IOException("Received message before mutually trust");
            }

            byte[] key = getInboundKey(context);
            byte[] plaintext;

            try {
                plaintext = messageCipher.decrypt(
                        message.getPayload(),
                        key
                );
            } finally {
                Arrays.fill(key, (byte) 0);
            }

            try {
                text = new String(plaintext, StandardCharsets.UTF_8);
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        }

        events.onMessageReceived(
                connection,
                context.state.getRemoteIdentity(),
                text
        );
    }

    public void handleTrustAccept(
            PeerConnection connection,
            ProtocolMessage message
    ) throws IOException, GeneralSecurityException {

        ConnectionContext context = getContext(connection);

        boolean established = false;
        boolean ignored = false;

        byte[] key = null;
        byte[] plaintext = null;

        try {
            synchronized (context) {
                if (context.state.getStatus() != HandshakeStatus.AUTHENTICATED) {
                    throw new IOException("Received TRUST_ACCEPT before authentication");
                }

                if (context.rejected || connections.get(connection) != context) {
                    ignored = true;
                } else {
                    key = getInboundKey(context);
                    plaintext = messageCipher.decrypt(message.getPayload(), key);

                    String payload = new String(
                            plaintext,
                            StandardCharsets.UTF_8
                    );

                    if (!TRUST_ACCEPT_PAYLOAD.equals(payload)) {
                        throw new IOException("Invalid TRUST_ACCEPT payload");
                    }

                    context.remoteTrusted = true;
                    established = establishTrustIfReady(context);
                }
            }
        } finally {
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }

            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }

        if (!ignored && established && connections.get(connection) == context) {
            events.onTrustEstablished(
                    connection,
                    context.state.getRemoteIdentity()
            );
        }
    }

    public void handleTrustReject(
            PeerConnection connection,
            ProtocolMessage message
    ) throws IOException, GeneralSecurityException {

        ConnectionContext context = getContext(connection);

        byte[] key = null;
        byte[] plaintext = null;

        try {
            synchronized (context) {
                if (context.state.getStatus() != HandshakeStatus.AUTHENTICATED) {
                    throw new IOException("Received TRUST_REJECT before authentication");
                }

                if (context.trustEstablished) {
                    throw new IOException(
                            "Received TRUST_REJECT after trust was established"
                    );
                }

                if (context.rejected) {
                    return;
                }

                key = getInboundKey(context);
                plaintext = messageCipher.decrypt(message.getPayload(), key);

                String payload = new String(
                        plaintext,
                        StandardCharsets.UTF_8
                );

                if (!TRUST_REJECT_PAYLOAD.equals(payload)) {
                    throw new IOException("Invalid TRUST_REJECT payload");
                }

                context.rejected = true;
                context.state.setStatus(HandshakeStatus.FAILED);
            }
        } finally {
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }

            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }

        closeRejectedConnection(connection, context);
    }

    private void closeRejectedConnection(
            PeerConnection connection,
            ConnectionContext context
    ) {

        synchronized (context) {
            context.rejected = true;
            context.state.setStatus(HandshakeStatus.FAILED);
        }

        if (connections.remove(connection, context)) {
            try {
                connection.close();
            } catch (IOException ignored) {
            }

            events.onDisconnected(connection);
        }
    }

    public void rejectConnection(PeerConnection connection)
            throws IOException, GeneralSecurityException {

        ConnectionContext context = getContext(connection);
        boolean rejectionStarted = false;

        try {
            synchronized (context) {

                if (context.state.getStatus() != HandshakeStatus.AUTHENTICATED) {
                    throw new IOException(
                            "Cannot reject connection before authentication"
                    );
                }

                if (context.trustEstablished) {
                    throw new IOException(
                            "Trust is already established"
                    );
                }

                if (context.rejected) {
                    return;
                }

                context.rejected = true;
                rejectionStarted = true;

                byte[] key = getOutboundKey(context);
                byte[] plaintext = TRUST_REJECT_PAYLOAD.getBytes(StandardCharsets.UTF_8);

                try {
                    byte[] encrypted = messageCipher.encrypt(plaintext, key);

                    send(connection, new ProtocolMessage(
                            MessageType.TRUST_REJECT,
                            encrypted
                    ));

                } finally {
                    Arrays.fill(key, (byte) 0);
                    Arrays.fill(plaintext, (byte) 0);
                }
            }

        } finally {
            if (rejectionStarted) {
                closeRejectedConnection(connection, context);
            }
        }
    }

    private boolean isMutuallyTrusted(ConnectionContext context) {
        return !context.rejected
                && context.localTrusted
                && context.remoteTrusted
                && context.trustEstablished;
    }

    private HandshakeService createHandshakeService(HandshakeState state) {
        return new HandshakeService(
                localIdentity,
                state,
                new ChallengeService(),
                new HandshakeCrypto()
        );
    }

    private IdentityPayload createLocalIdentityPayload() {
        return new IdentityPayload(
                localIdentity.getUserId(),
                localIdentity.getUsername(),
                localIdentity.getPublicKey()
        );
    }

    private ConnectionContext getContext(PeerConnection connection) throws IOException {
        ConnectionContext context = connections.get(connection);

        if (context == null) {
            throw new IOException("No active handshake for this connection");
        }

        return context;
    }

    private void send(
            PeerConnection connection,
            ProtocolMessage message
    ) throws IOException {
        connection.sendBytes(ProtocolSerializer.serialize(message));
    }

    private void failConnection(PeerConnection connection, Exception error) {
        ConnectionContext context = connections.remove(connection);

        if (context != null) {
            context.state.setStatus(HandshakeStatus.FAILED);
        }

        System.out.println("BeSafe protocol error: " + error.getMessage());

        events.onError(
                connection,
                error.getMessage()
        );

        try {
            connection.close();
        } catch (IOException ignored) {
        }
    }

    private byte[] getOutboundKey(ConnectionContext context) throws IOException {
        HandshakeSessionKeys keys = context.state.getSessionKeys();

        if (keys == null) {
            throw new IOException("Session keys are unavailable");
        }

        return context.initiator
                ? keys.getInitiatorToResponder()
                : keys.getResponderToInitiator();
    }

    private byte[] getInboundKey(ConnectionContext context) throws IOException {
        HandshakeSessionKeys keys = context.state.getSessionKeys();

        if (keys == null) {
            throw new IOException("Session keys are unavailable");
        }

        return context.initiator
                ? keys.getResponderToInitiator()
                : keys.getInitiatorToResponder();
    }

    private boolean establishTrustIfReady(ConnectionContext context) {
        if (context.localTrusted
                && context.remoteTrusted
                && !context.trustEstablished) {
            context.trustEstablished = true;
            return true;
        }

        return false;
    }

    public void trustConnection(PeerConnection connection) throws IOException, GeneralSecurityException {
        ConnectionContext context = getContext(connection);

        boolean established;

        synchronized (context) {
            if (context.state.getStatus() != HandshakeStatus.AUTHENTICATED) {
                throw new IOException(
                        "Cannot trust connection before authentication"
                );
            }

            if (context.rejected) {
                throw new IOException("Trust was already rejected.");
            }

            if (context.trustEstablished || context.localTrusted) {
                return;
            }

            byte[] key = getOutboundKey(context);
            byte[] plaintext = TRUST_ACCEPT_PAYLOAD.getBytes(StandardCharsets.UTF_8);

            try {
                byte[] encrypted = messageCipher.encrypt(plaintext, key);

                send(connection, new ProtocolMessage(
                        MessageType.TRUST_ACCEPT,
                        encrypted
                ));

                context.localTrusted = true;

                established = establishTrustIfReady(context);
            } finally {
                Arrays.fill(key, (byte) 0);
                Arrays.fill(plaintext, (byte) 0);
            }
        }

        if (established && connections.get(connection) == context) {
            events.onTrustEstablished(
                    connection,
                    context.state.getRemoteIdentity()
            );
        }
    }

    @Override
    public void onDisconnected(PeerConnection connection) {
        ConnectionContext context = connections.remove(connection);

        if (context != null) {
            events.onDisconnected(connection);
        }
    }

    private static class ConnectionContext {

        private final HandshakeState state;
        private final boolean initiator;

        private HandshakeService handshakeService;

        private boolean localTrusted = false;
        private boolean remoteTrusted = false;
        private boolean trustEstablished = false;
        private boolean rejected = false;

        public ConnectionContext(
                HandshakeState state,
                boolean initiator
        ) {
            this.state = state;
            this.initiator = initiator;
        }
    }

}
