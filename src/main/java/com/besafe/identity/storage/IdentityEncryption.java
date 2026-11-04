package com.besafe.identity.storage;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;

import java.security.SecureRandom;
import java.util.Arrays;

public class IdentityEncryption {

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 128;

    public SecretKey generateKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);

        return generator.generateKey();
    }

    public byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        byte[] encryptedData = cipher.doFinal(data);

        byte[] result = new byte[iv.length + encryptedData.length];

        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(
                encryptedData, 0,
                result, iv.length,
                encryptedData.length
        );

        return result;
    }

    public byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        byte[] iv = Arrays.copyOfRange(encryptedData, 0, IV_LENGTH);

        byte[] encryptedContent = Arrays.copyOfRange(
                encryptedData,
                IV_LENGTH,
                encryptedData.length
        );

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);

        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        return cipher.doFinal(encryptedContent);
    }

}
