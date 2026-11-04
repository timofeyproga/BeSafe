package com.besafe.contact;

import java.security.PublicKey;

public class Contact {

    private final String userId;
    private final String username;
    private final PublicKey publicKey;

    public Contact(String userId, String username, PublicKey publicKey) {
        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("UserId cannot be null or blank");
        }

        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username cannot be null or blank");
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
