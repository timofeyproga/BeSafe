package com.besafe.protocol;

public class HandshakeState {

    private final HandshakeRole role;

    private HandshakeStatus status = HandshakeStatus.INITIAL;

    private IdentityPayload remoteIdentity;

    private byte[] initiatorNonce;
    private byte[] responderNonce;

    public HandshakeState(HandshakeRole role) {
        if (role == null) {
            throw new IllegalArgumentException("Role cannot be null");
        }

        this.role = role;
    }

    public HandshakeRole getRole() {
        return role;
    }

    public HandshakeStatus getStatus() {
        return status;
    }

    public IdentityPayload getRemoteIdentity() {
        return remoteIdentity;
    }

    public byte[] getInitiatorNonce() {
        return initiatorNonce == null ? null : initiatorNonce.clone();
    }

    public byte[] getResponderNonce() {
        return responderNonce == null ? null : responderNonce.clone();
    }

    public void setRemoteIdentity(IdentityPayload remoteIdentity) {
        if (remoteIdentity == null) {
            throw new IllegalArgumentException("Identity cannot be null");
        }

        this.remoteIdentity = remoteIdentity;
    }

    public void setInitiatorNonce(byte[] nonce) {
        this.initiatorNonce = copyNonce(nonce);
    }

    public void setResponderNonce(byte[] nonce) {
        this.responderNonce = copyNonce(nonce);
    }

    public void setStatus(HandshakeStatus status) {
        if (status == null) {
            throw new IllegalArgumentException("Status cannot be null");
        }

        this.status = status;
    }

    private byte[] copyNonce(byte[] nonce) {
        if (nonce == null || nonce.length != 32) {
            throw new IllegalArgumentException("Nonce must contain 32 bytes");
        }

        return nonce.clone();
    }
}