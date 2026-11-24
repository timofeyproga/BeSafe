package com.besafe.identity.device;

import com.besafe.core.RegistrationService;
import com.besafe.identity.UserIdentity;

import java.util.Arrays;

public class DeviceCertificateSerializerTest {

    public static void main(String[] args) throws Exception {
        RegistrationService registrationService = new RegistrationService();

        DeviceKeyManager keyManager = new DeviceKeyManager();
        DeviceCertificateManager certificateManager = new DeviceCertificateManager();
        DeviceCertificateSerializer serializer = new DeviceCertificateSerializer();

        UserIdentity user = registrationService.createUser("test");

        DeviceIdentity device = keyManager.createDeviceIdentity(user);
        DeviceCertificate original = certificateManager.createCertificate(user, device);

        byte[] serialized = serializer.serialize(original);

        DeviceCertificate restored = serializer.deserialize(serialized);

        System.out.println(
                "UserId: preserved: " + original.getUserId().equals(restored.getUserId())
        );

        System.out.println(
                "DeviceId preserved: " + original.getDeviceId().equals(restored.getDeviceId())
        );

        System.out.println(
                "Public key preserved: " + Arrays.equals(
                        original.getDevicePublicKey().getEncoded(),
                        restored.getDevicePublicKey().getEncoded()
                )
        );

        System.out.println(
                "Signature preserved: " + Arrays.equals(
                        original.getSignature(),
                        restored.getSignature()
                )
        );

        System.out.println(
                "Certificate valid: " + certificateManager.verifyCertificate(user, restored)
        );

        byte[] corrupted = Arrays.copyOf(
                serialized,
                serialized.length - 1
        );

        try {
            serializer.deserialize(corrupted);
            System.out.println("Corrupted data: NOT DETECTED");
        } catch (Exception e) {
            System.out.println("Corrupted data: REJECTED");
        }
    }

}
