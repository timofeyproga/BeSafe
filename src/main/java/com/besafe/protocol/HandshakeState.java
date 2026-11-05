package com.besafe.protocol;

import java.security.KeyPair;
import java.security.PublicKey;

public class HandshakeState {

    private final HandshakeRole role;

    private HandshakeStatus status = HandshakeStatus.INITIAL;

    private IdentityPayload remoteIdentity;

    private KeyPair localEphemeralKeyPair;
    private PublicKey remoteEphemeralPublicKey;

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

    public void setLocalEphemeralKeyPair(KeyPair keyPair) {
        if (keyPair == null) {
            throw new IllegalArgumentException("KeyPair cannot be null");
        }

        this.localEphemeralKeyPair = keyPair;
    }

    public void setRemoteEphemeralPublicKey(PublicKey key) {
        if (key == null) {
            throw new IllegalArgumentException("PublicKey cannot be null");
        }

        String algorithm = key.getAlgorithm();

        if (!algorithm.equalsIgnoreCase("X25519")
                && !algorithm.equalsIgnoreCase("XDH")) {
            throw new IllegalArgumentException("Only X25519 keys are supported");
        }

        this.remoteEphemeralPublicKey = key;
    }

    public KeyPair getLocalEphemeralKeyPair() {
        return localEphemeralKeyPair;
    }

    public PublicKey getRemoteEphemeralPublicKey() {
        return remoteEphemeralPublicKey;
    }
}