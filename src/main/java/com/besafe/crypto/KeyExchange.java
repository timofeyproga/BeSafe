package com.besafe.crypto;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class KeyExchange {

    public KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519");

        return generator.generateKeyPair();
    }

    public byte[] generateSharedSecret(
            PrivateKey privatekey,
            PublicKey remotePublicKey
    ) throws GeneralSecurityException {
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");

        agreement.init(privatekey);
        agreement.doPhase(remotePublicKey, true);

        return agreement.generateSecret();
    }

    public PublicKey decodePublicKey(byte[] encodedKey)  throws GeneralSecurityException {
        KeyFactory factory = KeyFactory.getInstance("X25519");

        return factory.generatePublic(
                new X509EncodedKeySpec(encodedKey)
        );
    }

}
