package com.besafe.identity.device;

import java.security.KeyPair;

public class DeviceIdentity {

    private final String deviceId;
    private final String userId;
    private final KeyPair keyPair;

    public DeviceIdentity(
            String deviceId,
            String userId,
            KeyPair keyPair
    ) {
        if (deviceId == null || deviceId.isBlank()) {
            throw new IllegalArgumentException("DeviceId cannot be null or blank");
        }

        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("UserId cannot be null or blank");
        }

        if (keyPair == null || keyPair.getPrivate() == null || keyPair.getPublic() == null) {
            throw new IllegalArgumentException("Keys cannot be null");
        }

        this.deviceId = deviceId;
        this.userId = userId;
        this.keyPair = keyPair;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public String getUserId() {
        return userId;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

}
