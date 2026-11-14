package com.besafe.protocol;

import com.besafe.identity.UserIdentity;
import com.besafe.network.MessageHandler;
import com.besafe.network.PeerConnection;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ProtocolHandler implements MessageHandler {

    private final UserIdentity localIdentity;

    private final Map<PeerConnection, ConnectionContext> connections =
            new ConcurrentHashMap<>();

    public ProtocolHandler(UserIdentity localIdentity) {
        if (localIdentity == null) {
            throw new NullPointerException("LocalIdentity is null");
        }

        this.localIdentity = localIdentity;
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
                    connection.close();
                }

                default ->
                    throw new IOException("Unsupported protocol message: " + message.getType());

            }
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            failConnection(connection, e);
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

        if (context == null || context.handshakeService == null) {
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

        try {
            connection.close();
        } catch (IOException ignored) {
        }
    }

    @Override
    public void onDisconnected(PeerConnection connection) {
        connections.remove(connection);
    }

    private static class ConnectionContext {

        private final HandshakeState state;
        private final boolean initiator;

        private HandshakeService handshakeService;

        public ConnectionContext(
                HandshakeState state,
                boolean initiator
        ) {
            this.state = state;
            this.initiator = initiator;
        }
    }

}
