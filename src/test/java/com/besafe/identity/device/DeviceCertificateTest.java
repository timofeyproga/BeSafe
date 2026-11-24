package com.besafe.identity.device;

import com.besafe.core.RegistrationService;
import com.besafe.identity.UserIdentity;

public class DeviceCertificateTest {

    public static void main(String[] args) throws Exception {

        RegistrationService registrationService = new RegistrationService();
        DeviceKeyManager keyManager = new DeviceKeyManager();
        DeviceCertificateManager certificateManager = new DeviceCertificateManager();

        UserIdentity user = registrationService.createUser("test");
        DeviceIdentity device = keyManager.createDeviceIdentity(user);
        DeviceCertificate certificate = certificateManager.createCertificate(user, device);
        System.out.println("Valid certificate: " + certificateManager.verifyCertificate(user, certificate));

        UserIdentity anotheruser = registrationService.createUser("test2");

        System.out.println("another user: " + certificateManager.verifyCertificate(anotheruser, certificate));

        DeviceCertificate modifiedCertitficate = new DeviceCertificate(
                certificate.getUserId(),
                "0000000000000000000000000000000000000000000000000000000000000000",
                certificate.getDevicePublicKey(),
                certificate.getCreatedAt(),
                certificate.getSignature()
        );

        System.out.println("Modified certificate: " + certificateManager.verifyCertificate(user, modifiedCertitficate));
    }

}
