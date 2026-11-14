package com.besafe.protocol;

import com.besafe.network.PeerConnection;

public interface ProtocolEvents {

    default void onAuthenticated(
            PeerConnection connection,
            IdentityPayload remoteIdentity
    ) {
    }

    default void onMessageReceived(
            PeerConnection connection,
            IdentityPayload identity,
            String message
    ) {
    }

    default void onDisconnected(PeerConnection connection) {
    }

    default void onError(
            PeerConnection connection,
            String error
    ) {
    }

}
