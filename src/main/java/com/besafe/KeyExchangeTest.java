package com.besafe;

import com.besafe.crypto.KeyExchange;

import java.security.KeyPair;
import java.security.MessageDigest;

public class KeyExchangeTest {

    public static void main(String[] args) throws Exception {
        KeyExchange exchange = new KeyExchange();
        KeyPair aliceKeys = exchange.generateKeyPair();
        KeyPair bobKeys = exchange.generateKeyPair();

        byte[] aliceSecret = exchange.generateSharedSecret(
                aliceKeys.getPrivate(),
                bobKeys.getPublic()
        );

        byte[] bobSecret = exchange.generateSharedSecret(
                bobKeys.getPrivate(),
                aliceKeys.getPublic()
        );

        boolean identical = MessageDigest.isEqual(aliceSecret, bobSecret);

        System.out.println("Alice secret length: " + aliceSecret.length);
        System.out.println("Bob secret length: " + bobSecret.length);
        System.out.println("Secrets identical: " + identical);

        if (!identical) {
            throw new IllegalStateException("Key exchange failed!");
        }

        System.out.println("X25519 KEY EXCHANGE SUCCESS");
    }

}
