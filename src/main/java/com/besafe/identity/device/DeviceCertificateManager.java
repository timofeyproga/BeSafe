package com.besafe.identity.device;

import com.besafe.identity.UserIdentity;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.util.Objects;

public class DeviceCertificateManager {

    public DeviceCertificate createCertificate(
            UserIdentity user,
            DeviceIdentity device
    ) throws GeneralSecurityException, IOException {

        validateOwnership(user, device);

        long createdAt = System.currentTimeMillis();

        byte[] certificateData = createCertificateData(
                user.getUserId(),
                device.getDeviceId(),
                device.getKeyPair().getPublic().getEncoded(),
                createdAt
        );

        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(user.getPrivateKey());
        signer.update(certificateData);

        byte[] signature = signer.sign();

        return new DeviceCertificate(
                user.getUserId(),
                device.getDeviceId(),
                device.getKeyPair().getPublic(),
                createdAt,
                signature
        );
    }

    public boolean verifyCertificate(
            UserIdentity user,
            DeviceCertificate certificate
    ) throws GeneralSecurityException, IOException {
        if (user == null || certificate == null) {
            return false;
        }

        if (!Objects.equals(user.getUserId(), certificate.getUserId())) {
            return false;
        }

        DeviceKeyManager keyManager = new DeviceKeyManager();

        String calculatedDeviceId = keyManager.generateDeviceId(
                certificate.getDevicePublicKey()
        );

        if (!certificate.getDeviceId().equals(certificate.getDeviceId())) {
            return false;
        }

        byte[] certificateData = createCertificateData(
                certificate.getUserId(),
                certificate.getDeviceId(),
                certificate.getDevicePublicKey().getEncoded(),
                certificate.getCreatedAt()
        );

        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(user.getPublicKey());
        verifier.update(certificateData);

        return verifier.verify(certificate.getSignature());
    }

    private byte[] createCertificateData(
            String userId,
            String deviceId,
            byte[] publicKey,
            long createdAt
    ) throws IOException {

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(buffer);

        out.writeUTF(userId);
        out.writeUTF(deviceId);
        out.writeInt(publicKey.length);
        out.write(publicKey);
        out.writeLong(createdAt);

        out.flush();
        return buffer.toByteArray();
    }

    private void validateOwnership(
            UserIdentity user,
            DeviceIdentity device
    ) {
        if (user == null || device == null) {
            throw new IllegalArgumentException("Identity cannot be null");
        }

        if (!Objects.equals(user.getUserId(), device.getUserId())) {
            throw new IllegalArgumentException("Device belongs to another user");
        }
    }

}
