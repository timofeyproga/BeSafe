package com.besafe.identity.device;

import com.besafe.identity.IdentityKeyManager;
import com.besafe.identity.UserIdentity;
import com.besafe.identity.storage.CredentialStore;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class DeviceStorageManualTest {

    public static void main(String[] args) throws Exception {

        Path testDirectory = Files.createTempDirectory("besafe-device-test");
        String originalHome = System.getProperty("user.home");

        try {
            System.setProperty("user.home", testDirectory.toString());

            CredentialStore credentialStore = new MemoryCredentialStore();

            IdentityKeyManager identityKeyManager = new IdentityKeyManager();
            var identityKeyPair = identityKeyManager.generateKeyPair();

            String userId = identityKeyManager.generateUserId(
                    identityKeyPair.getPublic()
            );

            UserIdentity user = new UserIdentity(
                    "test",
                    userId,
                    identityKeyPair.getPublic(),
                    identityKeyPair.getPrivate()
            );

            DeviceKeyManager deviceKeyManager = new DeviceKeyManager();
            DeviceIdentity device = deviceKeyManager.createDeviceIdentity(user);

            DeviceCertificateManager certificateManager = new DeviceCertificateManager();
            DeviceCertificate certificate = certificateManager.createCertificate(user, device);

            DeviceStorage storage = new DeviceStorage(
                    credentialStore,
                    new DeviceIdentitySerializer(),
                    new DeviceCertificateSerializer(),
                    certificateManager,
                    deviceKeyManager
            );

            storage.save(user, device, certificate);

            System.out.println(
                    "Device file created: " + Files.exists(testDirectory.resolve("BeSafe/device.dat"))
            );

            StoredDevice loaded = storage.load(user);

            System.out.println(
                    "Device loaded: " + (loaded != null)
            );

            if (loaded == null) {
                throw new IllegalStateException("Device was not loaded");
            }

            DeviceIdentity loadedDevice = loaded.getDeviceIdentity();
            DeviceCertificate loadedCertificate = loaded.getCertificate();

            System.out.println(
                    "UserID preserved: " + user.getUserId().equals(loadedDevice.getUserId())
            );

            System.out.println(
                    "DeviceId preserved: " + device.getDeviceId().equals(loadedDevice.getDeviceId())
            );

            System.out.println(
                    "Public key preserved: " + Arrays.equals(
                            device.getKeyPair().getPublic().getEncoded(),
                            loadedDevice.getKeyPair().getPublic().getEncoded()
                    )
            );

            System.out.println(
                    "Certificate valid: " + certificateManager.verifyCertificate(
                            user,
                            loadedCertificate
                    )
            );

            System.out.println(
                    "DeviceID valid: " + deviceKeyManager.verifyDeviceId(loadedDevice)
            );

            System.out.println(
                    "Device and certificate match: " + loadedDevice.getDeviceId().equals(loadedCertificate.getDeviceId())
            );
        } finally {
            System.setProperty("user.home", originalHome);
        }

    }

    private static class MemoryCredentialStore implements CredentialStore {

        private final Map<String, byte[]> secrets = new HashMap<>();

        @Override
        public void saveSecret(String key, byte[] secret) {
            secrets.put(key, secret.clone());
        }

        @Override
        public byte[] loadSecret(String key) throws IOException {
            byte[] secret = secrets.get(key);

            if (secret == null) {
                throw new IOException("Secret not found: " + key);
            }

            return secret.clone();
        }

    }

}
