package com.besafe.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

public class MessageCipher {

    private static final String ALGORITHM = "AES/GCM/NoPadding";

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 128;
    private static final int KEY_LENGTH = 32;

    private static final int MAX_PLAINTEXT_SIZE = 1_048_576 - IV_LENGTH - 16;

    private static final SecureRandom RANDOM = new SecureRandom();

    public byte[] encrypt(byte[] plaintext, byte[] key) throws GeneralSecurityException {
        validateInput(plaintext, key);

        if (plaintext.length > MAX_PLAINTEXT_SIZE) {
            throw new IllegalArgumentException("Data cannot be larger than " + MAX_PLAINTEXT_SIZE);
        }

        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(iv);

        SecretKey secretKey = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH, iv));

        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] result = new byte[IV_LENGTH + ciphertext.length];

        System.arraycopy(iv, 0, result, 0, IV_LENGTH);

        System.arraycopy(
                ciphertext,
                0,
                result,
                IV_LENGTH,
                ciphertext.length
        );

        return result;
    }

    public byte[] decrypt(byte[] encrypted, byte[] key) throws GeneralSecurityException {
        validateInput(encrypted, key);

        if (encrypted.length > 1_048_576) {
            throw new GeneralSecurityException("Encrypted data is too large");
        }

        if (encrypted.length < IV_LENGTH + 16) {
            throw new GeneralSecurityException("Encrypted data is too short");
        }

        byte[] iv = Arrays.copyOfRange(encrypted, 0, IV_LENGTH);

        byte[] ciphertext = Arrays.copyOfRange(encrypted, IV_LENGTH, encrypted.length);

        SecretKey secretKey = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH, iv));

        return cipher.doFinal(ciphertext);
    }

    private void validateInput(byte[] data, byte[] key) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }

        if (key == null || key.length != KEY_LENGTH) {
            throw new IllegalArgumentException("AES key must contain exactly 32 bytes");
        }
    }

}
