package com.besafe;

import com.besafe.protocol.ChallengeService;
import com.besafe.protocol.HandshakeCrypto;
import com.besafe.protocol.HandshakeTranscript;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class HandshakeCryptoTest {

    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");

        KeyPair alice = generator.generateKeyPair();
        KeyPair bob = generator.generateKeyPair();

        ChallengeService challengeService = new ChallengeService();
        HandshakeCrypto crypto = new HandshakeCrypto();

        byte[] nonceA = challengeService.generateChallenge();
        byte[] nonceB = challengeService.generateChallenge();

        HandshakeTranscript transcript = new HandshakeTranscript(
                "alice-id",
                "bob-id",
                alice.getPublic(),
                bob.getPublic(),
                nonceA,
                nonceB
        );

        byte[] data = transcript.toByteArray();

        byte[] signature = crypto.sign(data, alice.getPrivate());

        boolean validSignature = crypto.verify(
                data,
                signature,
                alice.getPublic()
        );

        System.out.println("Valid signature: " + validSignature);

        byte[] modifiedData = data.clone();
        modifiedData[modifiedData.length - 1] ^= 1;

        boolean modifiedSignature = crypto.verify(
                modifiedData,
                signature,
                alice.getPublic()
        );

        System.out.println("Modified transcript: " + modifiedSignature);

        boolean wrongKey = crypto.verify(
                data,
                signature,
                bob.getPublic()
        );

        System.out.println("Wrong public key: " + wrongKey);

        byte[] wrongSignature = crypto.sign(data, bob.getPrivate());

        boolean wrongSigner = crypto.verify(
                data,
                wrongSignature,
                alice.getPublic()
        );

        System.out.println("Wrong signer: " + wrongSigner);

    }

}
