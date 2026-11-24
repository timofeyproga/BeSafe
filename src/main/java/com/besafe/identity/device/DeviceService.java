package com.besafe.identity.device;

import com.besafe.identity.UserIdentity;

public class DeviceService {

    private final DeviceKeyManager keyManager;
    private final DeviceCertificateManager certificateManager;
    private final DeviceStorage storage;

    public DeviceService(
            DeviceKeyManager keyManager,
            DeviceCertificateManager certificateManager,
            DeviceStorage storage
    ) {
        if (keyManager == null
                || certificateManager == null
                || storage == null) {
            throw new IllegalArgumentException(
                    "Device service dependencies cannot be null"
            );
        }

        this.keyManager = keyManager;
        this.certificateManager = certificateManager;
        this.storage = storage;
    }

    public StoredDevice createDevice(UserIdentity user) throws Exception {

        if (user == null) {
            throw new IllegalArgumentException(
                    "User identity cannot be null"
            );
        }

        DeviceIdentity device = keyManager.createDeviceIdentity(user);
        DeviceCertificate certificate = certificateManager.createCertificate(user, device);

        storage.save(user, device, certificate);

        return new StoredDevice(device, certificate);
    }

    public StoredDevice loadDevice(UserIdentity user) throws Exception {
        if (user == null) {
            throw new IllegalArgumentException(
                    "User identity cannot be null"
            );
        }

        return storage.load(user);
    }

    public StoredDevice loadOrCreateDevice(UserIdentity user) throws Exception {
        StoredDevice storedDevice = loadDevice(user);

        if (storedDevice != null) {
            return storedDevice;
        }

        return createDevice(user);
    }
}
