package com.besafe.identity;

import java.security.PrivateKey;
import java.security.PublicKey;

public class UserIdentity {

    private final String username;
    private final String userId;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public UserIdentity(
            String username,
            String userId,
            PublicKey publicKey,
            PrivateKey privateKey
    ) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username cannot be null or blank");
        }

        String normalizedName = username.trim();

        if (normalizedName.length() < 3 || normalizedName.length() > 32) {
            throw new IllegalArgumentException("Username length must be between 3 and 32 characters");
        }

        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("UserId cannot be null or blank");
        }

        if (publicKey == null || publicKey == null) {
            throw new IllegalArgumentException("Keys cannot be null or blank");
        }

        this.username = normalizedName;
        this.userId = userId;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String getUsername() {
        return username;
    }

    public String getUserId() {
        return userId;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

}
