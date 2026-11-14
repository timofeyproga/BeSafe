package com.besafe.network;

public interface MessageHandler {

    void onMessageReceived(PeerConnection connection, byte[] message);

    default void onDisconnected(PeerConnection connection) {
    }

}
