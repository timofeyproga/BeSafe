package com.besafe.protocol;

public class HandshakeSessionKeys {

    private final byte[] initiatorToResponer;
    private final byte[] responderToInitiator;
    private final byte[] responderConfirmation;
    private final byte[] initiatorConfirmation;

    public HandshakeSessionKeys(
            byte[] initiatorToResponer,
            byte[] responderToInitiator,
            byte[] responderConfirmation,
            byte[] initiatorConfirmation
    ) {
        this.initiatorToResponer = copyKey(initiatorToResponer);
        this.responderToInitiator = copyKey(responderToInitiator);
        this.responderConfirmation = copyKey(responderConfirmation);
        this.initiatorConfirmation = copyKey(initiatorConfirmation);
    }

    public byte[] getInitiatorToResponder() {
        return initiatorToResponer.clone();
    }

    public byte[] getResponderToInitiator() {
        return responderToInitiator.clone();
    }

    public byte[] getResponderConfirmation() {
        return responderConfirmation.clone();
    }

    public byte[] getInitiatorConfirmation() {
        return initiatorConfirmation.clone();
    }

    private byte[] copyKey(byte[] key) {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("Session keys must contain 32 bytes");
        }

        return key.clone();
    }

}
