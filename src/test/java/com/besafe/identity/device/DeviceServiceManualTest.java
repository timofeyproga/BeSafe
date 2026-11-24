package com.besafe.identity.device;

import com.besafe.identity.IdentityKeyManager;
import com.besafe.identity.UserIdentity;
import com.besafe.identity.storage.CredentialStore;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public class DeviceServiceManualTest {

    public static void main(String[] args) throws Exception {

        Path testDirectory = Files.createTempDirectory("besafe-service-test-");
        String originalHome = System.getProperty("user.home");

        try {
            System.setProperty("user.home", testDirectory.toString());

            CredentialStore credentialStore = new MemoryCredentialStore();

            IdentityKeyManager identityKeyManager = new IdentityKeyManager();
            var identityKeys = identityKeyManager.generateKeyPair();

            String userId = identityKeyManager.generateUserId(
                    identityKeys.getPublic()
            );

            UserIdentity user = new UserIdentity(
                    "test",
                    userId,
                    identityKeys.getPublic(),
                    identityKeys.getPrivate()
            );

            DeviceKeyManager keyManager = new DeviceKeyManager();
            DeviceCertificateManager certificateManager = new DeviceCertificateManager();

            DeviceStorage storage = new DeviceStorage(
                    credentialStore,
                    new DeviceIdentitySerializer(),
                    new DeviceCertificateSerializer(),
                    certificateManager,
                    keyManager
            );

            DeviceService service = new DeviceService(
                    keyManager,
                    certificateManager,
                    storage
            );

            StoredDevice first = service.loadOrCreateDevice(user);

            System.out.println(
                    "First device created: " + (first != null)
            );

            String originalDeviceId = first.getDeviceIdentity().getDeviceId();

            StoredDevice second = service.loadOrCreateDevice(user);

            System.out.println(
                    "Second device loaded: " + (second != null)
            );

            System.out.println(
                    "DeviceID unchanged: " + originalDeviceId.equals(
                            second.getDeviceIdentity().getDeviceId()
                    )
            );

            System.out.println(
                    "Certificate valid: " + certificateManager.verifyCertificate(
                            user,
                            second.getCertificate()
                    )
            );

            System.out.println(
                    "Device file exists: " + Files.exists(testDirectory.resolve("BeSafe/device.dat"))
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
