package com.besafe.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class KeyDerivation {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private static final int KEY_LENGTH = 32;
    private static final int SALT_LENGTH = 32;

    public byte[] deriveKey(
            byte[] sharedSecret,
            byte[] salt,
            byte[] info
    ) throws GeneralSecurityException {
        if (sharedSecret == null || sharedSecret.length == 0) {
            throw new IllegalArgumentException("Shared secret cannot be empty");
        }

        if (salt == null || salt.length != SALT_LENGTH) {
            throw new IllegalArgumentException("Salt must contain exactly 32 bytes");
        }

        if (info == null || info.length == 0) {
            throw new IllegalArgumentException("Info cannot be empty");
        }

        Mac mac = Mac.getInstance(HMAC_ALGORITHM);

        mac.init(new SecretKeySpec(sharedSecret, HMAC_ALGORITHM));

        byte[] pseudorandomKey = mac.doFinal(sharedSecret);

        try {
            mac.init(new SecretKeySpec(pseudorandomKey, HMAC_ALGORITHM));

            byte[] input = ByteBuffer.allocate(
                    info.length + 1
            ).put(info).put((byte) 0x01).array();

            return mac.doFinal(input);
        } finally {
            Arrays.fill(pseudorandomKey, (byte) 0);
        }
    }

}
