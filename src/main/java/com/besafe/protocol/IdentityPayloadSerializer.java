
package com.besafe.protocol;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;

public class IdentityPayloadSerializer {

    private static final int MAX_USERNAME_LENGTH = 128;
    private static final int MAX_USER_ID_LENGTH = 64;
    private static final int MAX_PUBLIC_KEY_LENGTH = 128;

    public static byte[] serialize(IdentityPayload identity)
            throws IOException {

        if (identity == null) {
            throw new IllegalArgumentException(
                    "Identity cannot be null"
            );
        }

        ByteArrayOutputStream byteStream =
                new ByteArrayOutputStream();

        DataOutputStream out =
                new DataOutputStream(byteStream);

        writeString(out, identity.getUserId());
        writeString(out, identity.getUsername());

        byte[] publicKey = identity.getPublicKey().getEncoded();

        if (publicKey.length > MAX_PUBLIC_KEY_LENGTH) {
            throw new IOException("Public key is too large");
        }

        out.writeInt(publicKey.length);
        out.write(publicKey);
        out.flush();

        return byteStream.toByteArray();
    }

    public static IdentityPayload deserialize(byte[] data)
            throws IOException {

        if (data == null) {
            throw new IllegalArgumentException(
                    "Data cannot be null"
            );
        }

        DataInputStream in = new DataInputStream(
                new ByteArrayInputStream(data)
        );

        String userId = readString(in, MAX_USER_ID_LENGTH);
        String username = readString(in, MAX_USERNAME_LENGTH);

        int keyLength = in.readInt();

        if (keyLength <= 0
                || keyLength > MAX_PUBLIC_KEY_LENGTH) {
            throw new IOException(
                    "Invalid public key length: " + keyLength
            );
        }

        byte[] keyBytes = in.readNBytes(keyLength);

        if (keyBytes.length != keyLength) {
            throw new EOFException("Incomplete public key data");
        }

        if (in.available() != 0) {
            throw new IOException("Unexpected trailing data");
        }

        try {
            KeyFactory keyFactory =
                    KeyFactory.getInstance("Ed25519");

            PublicKey publicKey = keyFactory.generatePublic(
                    new X509EncodedKeySpec(keyBytes)
            );

            String calculatedUserId = HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256")
                            .digest(keyBytes)
            );

            if (!MessageDigest.isEqual(
                    userId.getBytes(StandardCharsets.UTF_8),
                    calculatedUserId.getBytes(StandardCharsets.UTF_8)
            )) {
                throw new IOException(
                        "User ID does not match public key"
                );
            }

            return new IdentityPayload(
                    userId,
                    username,
                    publicKey
            );

        } catch (GeneralSecurityException e) {
            throw new IOException(
                    "Failed to restore public key", e
            );
        }
    }

    private static void writeString(
            DataOutputStream out,
            String value
    ) throws IOException {

        if (value == null || value.isBlank()) {
            throw new IOException("Invalid string");
        }

        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);

        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static String readString(
            DataInputStream in,
            int maxLength
    ) throws IOException {

        int length = in.readInt();

        if (length <= 0 || length > maxLength) {
            throw new IOException(
                    "Invalid string length: " + length
            );
        }

        byte[] bytes = in.readNBytes(length);

        if (bytes.length != length) {
            throw new EOFException("Incomplete string data");
        }

        return new String(bytes, StandardCharsets.UTF_8);
    }
}
