package com.besafe.protocol;

import java.security.PublicKey;

public class IdentityPayload {

    private final String userId;
    private final String username;
    private final PublicKey publicKey;

    public IdentityPayload(String userId, String username, PublicKey publicKey) {
        if (userId == null || userId.isEmpty()) {
            throw new IllegalArgumentException("UserId cannot be null or empty");
        }

        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }

        if (publicKey == null) {
            throw new IllegalArgumentException("PublicKey cannot be null");
        }

        this.userId = userId;
        this.username = username;
        this.publicKey = publicKey;
    }

    public String getUserId() {
        return userId;
    }

    public String getUsername() {
        return username;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
