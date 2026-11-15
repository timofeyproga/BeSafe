package com.besafe.ui;

import com.besafe.network.PeerConnection;
import com.besafe.protocol.IdentityPayload;
import com.besafe.protocol.ProtocolEvents;
import javafx.application.Platform;

import java.util.Objects;

public class JavaFxProtocolEvents implements ProtocolEvents {

    private volatile ProtocolEvents listener;

    public void setListener(ProtocolEvents listener) {
        this.listener = Objects.requireNonNull(listener);
    }

    @Override
    public void onAuthenticated(
            PeerConnection connection,
            IdentityPayload remoteIdentity
    ) {
        Platform.runLater(() -> {
            ProtocolEvents current = listener;
            if  (current != null) {
                current.onAuthenticated(connection, remoteIdentity);
            }
        });
    }

    @Override
    public void onMessageReceived(
            PeerConnection connection,
            IdentityPayload identity,
            String message
    ) {
        Platform.runLater(() -> {
            ProtocolEvents current = listener;
            if (current != null) {
                current.onMessageReceived(connection, identity, message);
            }
        });
    }

    @Override
    public void onDisconnected(PeerConnection connection) {
        Platform.runLater(() -> {
            ProtocolEvents current = listener;
            if (current != null) {
                current.onDisconnected(connection);
            }
        });
    }

    @Override
    public void onError(
            PeerConnection connection,
            String error
    ) {
        Platform.runLater(() -> {
            ProtocolEvents current = listener;
            if (current != null) {
                current.onError(connection, error);
            }
        });
    }

}
