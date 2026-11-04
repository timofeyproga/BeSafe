package com.besafe.identity.storage;

import com.besafe.identity.UserIdentity;

import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;

public class IdentitySerializer {

    public byte[] serialize(UserIdentity user) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();

        try (DataOutputStream out = new DataOutputStream(byteStream)) {
            out.writeInt(1);

            out.writeUTF(user.getUsername());
            out.writeUTF(user.getUserId());

            byte[] publicKey = user.getPublicKey().getEncoded();
            byte[] privateKey = user.getPrivateKey().getEncoded();

            out.writeInt(publicKey.length);
            out.write(publicKey);

            out.writeInt(privateKey.length);
            out.write(privateKey);
        }

        return byteStream.toByteArray();
    }

    public UserIdentity deserialize(byte[] data) throws IOException, GeneralSecurityException {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(data))) {

            int version = in.readInt();

            if (version != 1) {
                throw new IOException("Unsupported identity format version: " + version);
            }

            String username = in.readUTF();
            String userId = in.readUTF();

            int publicKeyLength = in.readInt();

            if (publicKeyLength <= 0 || publicKeyLength > 4096) {
                throw new IOException("Invalid public key length: " + publicKeyLength);
            }

            byte[] publicKeyBytes = in.readNBytes(publicKeyLength);

            if (publicKeyBytes.length != publicKeyLength) {
                throw new IOException("Invalid public key length: " + publicKeyLength);
            }

            int privateKeyLength = in.readInt();

            if (privateKeyLength <= 0 || privateKeyLength > 4096) {
                throw new IOException("Invalid private key length: " + privateKeyLength);
            }

            byte[] privateKeyBytes = in.readNBytes(privateKeyLength);

            if (privateKeyBytes.length != privateKeyLength) {
                throw new IOException("Invalid private key length: " + privateKeyLength);
            }

            if (in.available() != 0) {
                throw new IOException("Unexpected trailing identity data");
            }

            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");

            PublicKey publicKey = keyFactory.generatePublic(
                    new X509EncodedKeySpec(publicKeyBytes)
            );

            PrivateKey privateKey = keyFactory.generatePrivate(
                    new PKCS8EncodedKeySpec(privateKeyBytes)
            );

            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] calculatedHash = digest.digest(publicKey.getEncoded());

            String calculatedUserId = HexFormat.of().formatHex(calculatedHash);

            if (!calculatedUserId.equals(userId)) {
                throw new IOException("UserID does not match public key");
            }

            return new UserIdentity(username, userId, publicKey, privateKey);

        }
    }

}
