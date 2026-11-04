package com.besafe.protocol;

import java.security.*;

public class ChallengeService {

    private static final int CHALLENGE_SIZE = 32;

    public byte[] generateChallenge() {
        byte[] challenge = new byte[CHALLENGE_SIZE];

        SecureRandom random = new SecureRandom();
        random.nextBytes(challenge);

        return challenge;
    }

    public byte[] signChallenge(byte[] challenge, PrivateKey privateKey) throws GeneralSecurityException {
        if (challenge == null || privateKey == null) {
            throw new NullPointerException("Challenge or privateKey is null");
        }

        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(privateKey);
        signature.update(challenge);

        return signature.sign();
    }

    public boolean verifyChallenge(
            byte[] challenge,
            byte[] signedChallenge,
            PublicKey publicKey
    ) throws GeneralSecurityException {
        if (challenge == null || signedChallenge == null || publicKey == null) {
            return false;
        }

        Signature signature = Signature.getInstance("Ed25519");
        signature.initVerify(publicKey);
        signature.update(challenge);

        return signature.verify(signedChallenge);
    }

}
