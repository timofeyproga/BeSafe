package com.besafe.identity.device;

import java.security.PublicKey;

public class DeviceCertificate {

    private final String userId;
    private final String deviceId;
    private final PublicKey devicePublicKey;
    private final long createdAt;
    private final byte[] signature;

    public DeviceCertificate(
            String userId,
            String deviceId,
            PublicKey devicePublicKey,
            long createdAt,
            byte[] signature
    ) {
        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("User cannot be null or blank");
        }

        if (deviceId == null || deviceId.isBlank()) {
            throw new IllegalArgumentException("DeviceId cannot be null or blank");
        }

        if (devicePublicKey == null) {
            throw new IllegalArgumentException("DevicePublicKey cannot be null");
        }

        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be empty");
        }

        this.userId = userId;
        this.deviceId = deviceId;
        this.devicePublicKey = devicePublicKey;
        this.createdAt = createdAt;
        this.signature = signature;
    }

    public String getUserId() {
        return userId;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public PublicKey getDevicePublicKey() {
        return devicePublicKey;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public byte[] getSignature() {
        return signature.clone();
    }

}
