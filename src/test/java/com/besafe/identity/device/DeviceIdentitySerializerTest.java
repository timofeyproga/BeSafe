
package com.besafe.identity.device;

import com.besafe.core.RegistrationService;
import com.besafe.identity.UserIdentity;

public class DeviceIdentitySerializerTest {

    public static void main(String[] args) throws Exception {

        RegistrationService registrationService = new RegistrationService();
        DeviceKeyManager keyManager = new DeviceKeyManager();
        DeviceIdentitySerializer serializer = new DeviceIdentitySerializer();
        DeviceCertificateManager certificateManager = new DeviceCertificateManager();

        UserIdentity user = registrationService.createUser("test");
        DeviceIdentity original = keyManager.createDeviceIdentity(user);
        DeviceCertificate certificate = certificateManager.createCertificate(user, original);

        byte[] serialized = serializer.serialize(original);

        DeviceIdentity restored = serializer.deserialize(
                serialized,
                original.getKeyPair().getPrivate()
        );

        System.out.println(
                "UserID preserved: " + original.getUserId().equals(restored.getUserId())
        );

        System.out.println(
                "DeviceID preserved: " + original.getDeviceId().equals(restored.getDeviceId())
        );

        System.out.println(
                "Key pair valid: " + keyManager.verifyDeviceId(restored)
        );

        System.out.println(
                "Certificate valid: " + certificateManager.verifyCertificate(user, certificate)
        );

        DeviceIdentity anotherDevice = keyManager.createDeviceIdentity(user);

        try {
            serializer.deserialize(
                    serialized,
                    anotherDevice.getKeyPair().getPrivate()
            );

            System.out.println("Wrong private key: NOT DETECTED");

        } catch (Exception exception) {
            System.out.println("Wrong private key: REJECTED");
        }
    }
}
