package com.besafe.identity.device;

import com.besafe.identity.UserIdentity;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.HexFormat;

public class DeviceKeyManager {

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        return keyPairGenerator.generateKeyPair();
    }

    public String generateDeviceId(PublicKey publicKey) throws NoSuchAlgorithmException {
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }

        byte[] publicKeyBytes = publicKey.getEncoded();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(publicKeyBytes);
        return HexFormat.of().formatHex(hash);
    }

    public DeviceIdentity createDeviceIdentity(UserIdentity user) throws NoSuchAlgorithmException {
        if (user == null) {
            throw new IllegalArgumentException("User cannot be null");
        }

        KeyPair keyPair = generateKeyPair();

        String deviceId = generateDeviceId(keyPair.getPublic());

        return new DeviceIdentity(
                deviceId,
                user.getUserId(),
                keyPair
        );
    }

    public boolean verifyDeviceId(DeviceIdentity device) throws NoSuchAlgorithmException {
        if (device == null || device.getKeyPair() == null) {
            return false;
        }

        String calculatedDeviceId = generateDeviceId(device.getKeyPair().getPublic());

        return calculatedDeviceId.equals(device.getDeviceId());
    }

}
