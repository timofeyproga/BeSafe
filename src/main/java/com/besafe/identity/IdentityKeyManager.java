package com.besafe.identity;

import java.security.*;
import java.util.HexFormat;

public class IdentityKeyManager {

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        return generator.generateKeyPair();
    }

    public PublicKey getPublicKey(KeyPair keyPair) {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey(KeyPair keyPair) {
        return keyPair.getPrivate();
    }

    public String generateUserId(PublicKey publicKey) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] publickeyBytes = publicKey.getEncoded();
        byte[] hash = digest.digest(publickeyBytes);

        return HexFormat.of().formatHex(hash);
    }

}
