package com.besafe.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class DirectionalKeyTest {

    public static void main(String[] args) throws Exception {

        KeyExchange exchange = new KeyExchange();
        KeyDerivation derivation = new KeyDerivation();

        var alice = exchange.generateKeyPair();
        var bob = exchange.generateKeyPair();

        byte[] aliceSecret = exchange.generateSharedSecret(
                alice.getPrivate(),
                bob.getPublic()
        );

        byte[] bobSecret = exchange.generateSharedSecret(
                bob.getPrivate(),
                alice.getPublic()
        );

        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);

        byte[] initiatorToResponder =
                "BeSafe-v1|initiator-to-responder"
                        .getBytes(StandardCharsets.UTF_8);

        byte[] responderToInitiator =
                "BeSafe-v1|responder-to-initiator"
                        .getBytes(StandardCharsets.UTF_8);

        // Alice's sending key
        byte[] aliceSendKey = derivation.deriveKey(
                aliceSecret,
                salt,
                initiatorToResponder
        );

        // Bob's receiving key
        byte[] bobReceiveKey = derivation.deriveKey(
                bobSecret,
                salt,
                initiatorToResponder
        );

        // Bob's sending key
        byte[] bobSendKey = derivation.deriveKey(
                bobSecret,
                salt,
                responderToInitiator
        );

        // Alice's receiving key
        byte[] aliceReceiveKey = derivation.deriveKey(
                aliceSecret,
                salt,
                responderToInitiator
        );

        boolean forwardMatches = MessageDigest.isEqual(
                aliceSendKey,
                bobReceiveKey
        );

        boolean reverseMatches = MessageDigest.isEqual(
                bobSendKey,
                aliceReceiveKey
        );

        boolean directionsSeparated = !MessageDigest.isEqual(
                aliceSendKey,
                bobSendKey
        );

        System.out.println(
                "Alice -> Bob keys match: " + forwardMatches
        );

        System.out.println(
                "Bob -> Alice keys match: " + reverseMatches
        );

        System.out.println(
                "Direction keys are different: " + directionsSeparated
        );

        if (!forwardMatches || !reverseMatches || !directionsSeparated) {
            throw new IllegalStateException(
                    "Directional key derivation failed!"
            );
        }

        System.out.println("DIRECTIONAL KEY DERIVATION SUCCESS!");
    }
}
