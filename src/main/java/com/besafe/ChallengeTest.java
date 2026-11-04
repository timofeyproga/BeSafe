package com.besafe;

import com.besafe.protocol.ChallengeService;

import java.security.*;

public class ChallengeTest {

    public static void main(String[] args) throws Exception {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = generator.generateKeyPair();

        ChallengeService service = new ChallengeService();

        byte[] challenge = service.generateChallenge();

        byte[] signedChallenge = service.signChallenge(
                challenge,
                keyPair.getPrivate()
        );

        boolean valid = service.verifyChallenge(
                challenge,
                signedChallenge,
                keyPair.getPublic()
        );

        System.out.println("Signature valid: " + valid);

        challenge[0] ^= 1;

        boolean tampered = service.verifyChallenge(
                challenge,
                signedChallenge,
                keyPair.getPublic()
        );

        System.out.println("Tampered challenge valid: " + tampered);
    }
}