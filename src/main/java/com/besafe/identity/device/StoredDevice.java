package com.besafe.identity.device;

public class StoredDevice {

    private final DeviceIdentity deviceIdentity;
    private final DeviceCertificate certificate;

    public StoredDevice(
            DeviceIdentity deviceIdentity,
            DeviceCertificate certificate
    ) {
        if (deviceIdentity == null) {
            throw new IllegalArgumentException("Device cannot be null");
        }

        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }

        this.deviceIdentity = deviceIdentity;
        this.certificate = certificate;
    }

    public DeviceIdentity getDeviceIdentity() {
        return deviceIdentity;
    }

    public DeviceCertificate getCertificate() {
        return certificate;
    }
}
