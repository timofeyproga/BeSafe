package com.besafe.network;

public interface MessageHandler {

    void onMessageReceived(PeerConnection connection, byte[] message);

}
