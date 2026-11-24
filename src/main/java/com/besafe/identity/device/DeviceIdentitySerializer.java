package com.besafe.identity.device;

import java.io.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class DeviceIdentitySerializer {

    private static final int MAGIC = 0x42534449;
    private static final int FORMAT_VERSION = 1;
    private static final int MAX_KEY_LENGTH = 4096;

    public byte[] serialize(DeviceIdentity device) throws IOException {
        if (device == null) {
            throw new IllegalArgumentException("Device identity is null");
        }

        byte[] publicKey = device.getKeyPair().getPublic().getEncoded();

        try {
            validateKeyPair(
                    device.getKeyPair().getPublic(),
                    device.getKeyPair().getPrivate()
            );
        } catch (GeneralSecurityException e) {
            throw new IOException("Invalid device key pair", e);
        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(MAGIC);
            out.writeInt(FORMAT_VERSION);

            out.writeUTF(device.getUserId());
            out.writeUTF(device.getDeviceId());

            out.writeInt(publicKey.length);
            out.write(publicKey);
        }

        return buffer.toByteArray();
    }

    public DeviceIdentity deserialize(byte[] data, PrivateKey privateKey) throws IOException{
        if (data == null || data.length == 0) {
            throw new IOException("Device data is null");
        }

        if (privateKey == null) {
            throw new IllegalArgumentException("Private key is null");
        }

        try (DataInputStream in = new DataInputStream(
                new ByteArrayInputStream(data))) {

            if (in.readInt() != MAGIC) {
                throw new IOException("Invalid device file");
            }

            if (in.readInt() != FORMAT_VERSION) {
                throw new IOException("Unsupported device format");
            }

            String userId = in.readUTF();
            String deviceId = in.readUTF();

            int keyLength = in.readInt();

            if (keyLength <= 0 || keyLength > MAX_KEY_LENGTH) {
                throw new IOException("Invalid public key length");
            }

            byte[] publicKeyBytes = in.readNBytes(keyLength);

            if (publicKeyBytes.length != keyLength) {
                throw new IOException("Incomplete public key length");
            }

            if (in.read() != -1) {
                throw new IOException("Unexpected trailing data");
            }

            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");

            PublicKey publicKey = keyFactory.generatePublic(
                    new X509EncodedKeySpec(publicKeyBytes)
            );

            DeviceKeyManager keyManager = new DeviceKeyManager();

            String calculatedDeviceId = keyManager.generateDeviceId(publicKey);

            if (!calculatedDeviceId.equals(deviceId)) {
                throw new IOException("DeviceID does not match public key");
            }

            validateKeyPair(publicKey, privateKey);

            KeyPair keyPair = new KeyPair(publicKey, privateKey);

            return new DeviceIdentity(
                    deviceId,
                    userId,
                    keyPair
            );

        } catch (IOException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new IOException("Failed to restore device identity", e);
        }
    }

    private void validateKeyPair(
            PublicKey publicKey,
            PrivateKey privateKey
    ) throws GeneralSecurityException {

        byte[] challenge = "BeSafe Device Key Validation".getBytes();

        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(privateKey);
        signer.update(challenge);

        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update(challenge);

        if (!verifier.verify(signature)) {
            throw new InvalidKeyException("Public and private keys do not match");
        }
    }

}
