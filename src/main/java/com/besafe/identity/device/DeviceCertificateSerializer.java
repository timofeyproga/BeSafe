package com.besafe.identity.device;

import java.io.*;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class DeviceCertificateSerializer {

    private static final int FORMAT_VERSION = 1;
    private static final int MAX_FIELD_LENGTH = 4096;

    public byte[] serialize(DeviceCertificate certificate) throws IOException {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(buffer);

        out.writeInt(FORMAT_VERSION);
        out.writeUTF(certificate.getUserId());
        out.writeUTF(certificate.getDeviceId());

        byte[] publicKey = certificate.getDevicePublicKey().getEncoded();
        byte[] signature = certificate.getSignature();

        out.writeInt(publicKey.length);
        out.write(publicKey);

        out.writeLong(certificate.getCreatedAt());

        out.writeInt(signature.length);
        out.write(signature);

        out.flush();

        return buffer.toByteArray();
    }

    public DeviceCertificate deserialize(byte[] data) throws IOException {
        if (data == null || data.length == 0) {
            throw new IOException("Certificate data is empty");
        }

        try (DataInputStream in = new DataInputStream(
                new ByteArrayInputStream(data))) {

            int version = in.readInt();

            if (version != FORMAT_VERSION) {
                throw new IOException("Unsupported version: " + version);
            }

            String userId = in.readUTF();
            String deviceId = in.readUTF();

            int publicKeyLength = in.readInt();

            if (publicKeyLength < 0 || publicKeyLength > MAX_FIELD_LENGTH) {
                throw new IOException("Invalid public key length");
            }

            byte[] publicKeyBytes = in.readNBytes(publicKeyLength);

            if (publicKeyBytes.length != publicKeyLength) {
                throw new IOException("Incomplete public key data");
            }

            long createdAt = in.readLong();

            int signatureLength = in.readInt();

            if (signatureLength < 0 || signatureLength > MAX_FIELD_LENGTH) {
                throw new IOException("Invalid signature length");
            }

            byte[] signature = in.readNBytes(signatureLength);

            if (signature.length != signatureLength) {
                throw new IOException("Incomplete signature data");
            }

            if (in.read() != -1) {
                throw new IOException("Unexpected trailing data");
            }

            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");

            PublicKey publicKey = keyFactory.generatePublic(
                    new X509EncodedKeySpec(publicKeyBytes)
            );

            return new DeviceCertificate(
                    userId,
                    deviceId,
                    publicKey,
                    createdAt,
                    signature
            );
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to deserialize certificate", e);
        }
    }

}
