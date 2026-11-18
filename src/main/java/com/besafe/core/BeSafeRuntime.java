package com.besafe.core;

import com.besafe.contact.ContactService;
import com.besafe.conversation.ConversationService;
import com.besafe.identity.UserIdentity;
import com.besafe.network.NetworkManager;
import com.besafe.network.PeerAddress;
import com.besafe.network.PeerConnection;
import com.besafe.protocol.ProtocolEvents;
import com.besafe.protocol.ProtocolHandler;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class BeSafeRuntime implements AutoCloseable {

    private final UserIdentity localIdentity;

    private final ContactService contactService;
    private final ConversationService conversationService;

    private final ProtocolHandler protocolHandler;
    private final NetworkManager networkManager;

    public BeSafeRuntime(
            UserIdentity localIdentity,
            ProtocolEvents events
    ) {
        if (localIdentity == null || events == null) {
            throw new NullPointerException("LocalIdentity or events are null");
        }

        this.localIdentity = localIdentity;
        this.contactService = new ContactService();
        this.conversationService = new ConversationService();

        this.protocolHandler = new ProtocolHandler(
                localIdentity,
                events
        );

        this.networkManager = new NetworkManager(
                protocolHandler
        );
    }

    public void startServer(int port) throws IOException {
        networkManager.startServer(port);
    }

    public PeerConnection connect(PeerAddress address) throws IOException, GeneralSecurityException {
        if (address == null) {
            throw new IllegalArgumentException("Peer address cannot be null");
        }

        PeerConnection connection = networkManager.connect(
                address.getHost(),
                address.getPort()
        );

        try {
            protocolHandler.startIdentityExchange(connection);
            return connection;
        } catch (IOException e) {
            networkManager.disconnect(connection);
            throw e;
        }

    }

    public void sendMessage(
            PeerConnection connection,
            String message
    ) throws IOException, GeneralSecurityException {
        protocolHandler.sendChatMessage(connection, message);
    }

    public void disconnect(PeerConnection connection) {
        networkManager.disconnect(connection);
    }

    public void trustConnection(PeerConnection connection) throws IOException, GeneralSecurityException {
        protocolHandler.trustConnection(connection);
    }

    public void rejectConnection(PeerConnection connection) throws IOException, GeneralSecurityException {
        protocolHandler.rejectConnection(connection);
    }

    public UserIdentity getLocalIdentity() {
        return localIdentity;
    }

    public ContactService getContactService() {
        return contactService;
    }

    public ConversationService getConversationService() {
        return conversationService;
    }

    public NetworkManager getNetworkManager() {
        return networkManager;
    }

    @Override
    public void close() {
        networkManager.close();
    }

}
