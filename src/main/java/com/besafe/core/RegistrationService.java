package com.besafe.core;

import com.besafe.identity.IdentityKeyManager;
import com.besafe.identity.UserIdentity;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RegistrationService {

    private final IdentityKeyManager keyManager;

    public RegistrationService() {
        this.keyManager = new IdentityKeyManager();
    }

    public UserIdentity createUser(String username) throws NoSuchAlgorithmException {
        KeyPair keyPair = keyManager.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String userId = keyManager.generateUserId(publicKey);

        return new UserIdentity(username, userId, publicKey, privateKey);
    }

}
