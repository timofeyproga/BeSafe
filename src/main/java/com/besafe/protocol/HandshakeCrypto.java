package com.besafe.protocol;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class HandshakeCrypto {

    public byte[] sign(byte[] transcript, PrivateKey privateKey) throws GeneralSecurityException {
        if (transcript == null || privateKey == null) {
            throw new NullPointerException("Transcript or privateKey is null");
        }

        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(privateKey);
        signature.update(transcript);

        return signature.sign();
    }

    public boolean verify(
            byte[] transcript,
            byte[] signedTranscript,
            PublicKey publicKey
    ) throws GeneralSecurityException {
        if (transcript == null || signedTranscript == null || publicKey == null) {
            return false;
        }

        Signature signature = Signature.getInstance("Ed25519");
        signature.initVerify(publicKey);
        signature.update(transcript);

        return signature.verify(signedTranscript);
    }

}
