package com.besafe.identity;

import java.security.*;
import java.util.HexFormat;

public class IdentityValidator {

    private static final int CHALLENGE_LENGTH = 32;

    private final SecureRandom random = new SecureRandom();

    public void validate(UserIdentity identity) throws GeneralSecurityException {
        if (identity == null) {
            throw new IllegalArgumentException("UserIdentity cannot be null");
        }

        validate(
                identity.getPublicKey(),
                identity.getPrivateKey(),
                identity.getUserId()
        );
    }

    public void validate(
            PublicKey publicKey,
            PrivateKey privateKey,
            String userId
    ) throws GeneralSecurityException {
        // Checking enter data

        if (publicKey == null || privateKey == null) {
            throw new InvalidKeyException("Keys cannot be null or blank");
        }

        if (userId == null || userId.isBlank()) {
            throw new GeneralSecurityException("User ID cannot be null or blank");
        }

        // Does UserId match public key

        byte[] publicKeyBytes = publicKey.getEncoded();

        if (publicKeyBytes == null) {
            throw new InvalidKeyException("Public key cannot be encoded");
        }

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] hash = digest.digest(publicKeyBytes);

        String calculatedUserId = HexFormat.of().formatHex(hash);

        if (!userId.equals(calculatedUserId)) {
            throw new GeneralSecurityException("User ID does not match public key");
        }

        // Verify that keys from one KeyPair

        byte[] challenge = new byte[CHALLENGE_LENGTH];
        random.nextBytes(challenge);

        Signature signer = Signature.getInstance("Ed25519");

        signer.initSign(privateKey);
        signer.update(challenge);

        byte[] signedChallenge = signer.sign();

        Signature verifier = Signature.getInstance("Ed25519");

        verifier.initVerify(publicKey);
        verifier.update(challenge);

        if (!verifier.verify(signedChallenge)) {
            throw new InvalidKeyException("Private key does not match public key");
        }
    }

}
