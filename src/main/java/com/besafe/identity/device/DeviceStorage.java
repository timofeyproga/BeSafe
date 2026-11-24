package com.besafe.identity.device;

import com.besafe.Main;
import com.besafe.identity.UserIdentity;
import com.besafe.identity.storage.CredentialStore;

import java.io.*;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class DeviceStorage {

    private static final int MAGIC = 0x42534453;
    private static final int FORMAT_VERSION = 1;

    private static final int MAX_FILE_SIZE = 1024 * 1024;
    private static final int MAX_COMPONENT_SIZE = 512 * 1024;

    private final Path directory =
            Path.of(System.getProperty("user.home"), "BeSafe");

    private final Path deviceFile =
            directory.resolve("device.dat");

    private final CredentialStore credentialStore;
    private final DeviceIdentitySerializer identitySerializer;
    private final DeviceCertificateSerializer certificateSerializer;
    private final DeviceCertificateManager certificateManager;
    private final DeviceKeyManager keyManager;

    public DeviceStorage(
            CredentialStore credentialStore,
            DeviceIdentitySerializer identitySerializer,
            DeviceCertificateSerializer certificateSerializer,
            DeviceCertificateManager certificateManager,
            DeviceKeyManager keyManager
    ) {
        this.credentialStore = credentialStore;
        this.identitySerializer = identitySerializer;
        this.certificateSerializer = certificateSerializer;
        this.certificateManager = certificateManager;
        this.keyManager = keyManager;
    }

    public void save(
            UserIdentity user,
            DeviceIdentity device,
            DeviceCertificate certificate
    ) throws Exception {

        if (user == null || device == null || certificate == null) {
            throw new IllegalArgumentException("User, device and certificate cannot be null");
        }

        if (!user.getUserId().equals(device.getUserId())) {
            throw new IOException("Device belongs to another user");
        }

        if (!user.getUserId().equals(certificate.getUserId())) {
            throw new IOException("Certificate belongs to another user");
        }

        if (!device.getDeviceId().equals(certificate.getDeviceId())) {
            throw new IOException("DeviceID mismatch");
        }

        if (!keyManager.verifyDeviceId(device)) {
            throw new IOException("Invalid DeviceID");
        }

        if (!Arrays.equals(
                device.getKeyPair().getPublic().getEncoded(),
                certificate.getDevicePublicKey().getEncoded()
        )) {
            throw new IOException("Device public key mismatch");
        }

        if (!certificateManager.verifyCertificate(user, certificate)) {
            throw new IOException("Invalid device certificate");
        }

        byte[] identityData = identitySerializer.serialize(device);
        byte[] certificateData = certificateSerializer.serialize(certificate);
        byte[] privateKeyBytes = device.getKeyPair().getPrivate().getEncoded();

        if (privateKeyBytes == null) {
            throw new IOException("Device private key cannot be encoded");
        }

        try {
            Files.createDirectories(directory);

            byte[] fileData = createFileData(
                    device,
                    identityData,
                    certificateData
            );

            String credentialKey = createCredentialKey(
                    device.getUserId(),
                    device.getDeviceId()
            );

            credentialStore.saveSecret(credentialKey, privateKeyBytes);

            writeAtomically(fileData);
        } finally {
            Arrays.fill(privateKeyBytes, (byte) 0);
        }
    }

    public StoredDevice load(UserIdentity user) throws Exception {
        if (user == null) {
            throw new IllegalArgumentException("User cannot be null");
        }

        if (!Files.exists(deviceFile)) {
            return null;
        }

        long fileSize = Files.size(deviceFile);

        if (fileSize <= 0 || fileSize > MAX_FILE_SIZE) {
            throw new IOException("Invalid device file size");
        }

        byte[] fileData = Files.readAllBytes(deviceFile);

        StoredData storedData = parseFileData(fileData);

        if (!user.getUserId().equals(storedData.userId)) {
            throw new IOException("Stored device belongs to another user");
        }

        String credentialKey = createCredentialKey(
                storedData.userId,
                storedData.deviceId
        );

        byte[] privateKeyBytes;

        try {
            privateKeyBytes = credentialStore.loadSecret(credentialKey);
        } catch (IOException e) {
            throw new IOException(
                    "Device private key is missing from Window Credential Manager",
                    e
            );
        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");

            var privateKey = keyFactory.generatePrivate(
                    new PKCS8EncodedKeySpec(privateKeyBytes)
            );

            DeviceIdentity device = identitySerializer.deserialize(
                    storedData.identityData,
                    privateKey
            );

            DeviceCertificate certificate = certificateSerializer.deserialize(
                    storedData.certificateData
            );

            if (!storedData.userId.equals(device.getUserId())
                    || !storedData.deviceId.equals(device.getDeviceId())) {
                throw new IOException("Stored device metadata mismatch");
            }

            if (!device.getUserId().equals(certificate.getUserId())
                    || !device.getDeviceId().equals(certificate.getDeviceId())) {
                throw new IOException("Device certificate mismatch");
            }

            if (!Arrays.equals(
                    device.getKeyPair().getPublic().getEncoded(),
                    certificate.getDevicePublicKey().getEncoded()
            )) {
                throw new IOException("Device public key mismatch");
            }

            if (!keyManager.verifyDeviceId(device)) {
                throw new IOException("Invalid DeviceID");
            }

            if (!certificateManager.verifyCertificate(user, certificate)) {
                throw new IOException("Device certificate verification failed");
            }

            return new StoredDevice(device, certificate);
        } finally {
            Arrays.fill(privateKeyBytes, (byte) 0);
        }
    }

    private byte[] createFileData(
            DeviceIdentity device,
            byte[] identityData,
            byte[] certificateData
    ) throws IOException {

        if (identityData.length <= 0
                || identityData.length > MAX_COMPONENT_SIZE
                || certificateData.length <= 0
                || certificateData.length > MAX_COMPONENT_SIZE) {

            throw new IOException("Invalid device data size");
        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(buffer);

        out.writeInt(MAGIC);
        out.writeInt(FORMAT_VERSION);

        out.writeUTF(device.getUserId());
        out.writeUTF(device.getDeviceId());

        out.writeInt(identityData.length);
        out.write(identityData);

        out.writeInt(certificateData.length);
        out.write(certificateData);

        out.flush();

        byte[] result = buffer.toByteArray();

        if (result.length > MAX_FILE_SIZE) {
            throw new IOException("Device file is too large");
        }

        return result;
    }

    private StoredData parseFileData(byte[] fileData) throws IOException {
        DataInputStream in = new DataInputStream(
                new ByteArrayInputStream(fileData)
        );

        int magic = in.readInt();
        int version = in.readInt();

        if (magic != MAGIC) {
            throw new IOException("Invalid device file format");
        }

        if (version != FORMAT_VERSION) {
            throw new IOException("Invalid device file version");
        }

        String userId = in.readUTF();
        String deviceId = in.readUTF();

        if (userId.isBlank() || deviceId.isBlank()) {
            throw new IOException("Invalid device metadata");
        }

        byte[] identityData = readComponent(in);
        byte[] certificateData = readComponent(in);

        if (in.read() != -1) {
            throw new IOException("Unexpected data at end of device file");
        }

        return new StoredData(
                userId,
                deviceId,
                identityData,
                certificateData
        );
    }

    private byte[] readComponent(DataInputStream in) throws IOException {
        int length = in.readInt();

        if (length <= 0 || length > MAX_COMPONENT_SIZE) {
            throw new IOException("Invalid device data component length");
        }

        byte[] data = new byte[length];
        in.readFully(data);

        return data;
    }

    private void writeAtomically(byte[] data) throws IOException {
        Path tempFile = Files.createTempFile(
                directory,
                "device-",
                ".tmp"
        );

        try {
            Files.write(tempFile, data);

            try {
                Files.move(
                        tempFile,
                        deviceFile,
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE
                );
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(
                        tempFile,
                        deviceFile,
                        StandardCopyOption.REPLACE_EXISTING
                );
            }
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    private String createCredentialKey(String userId, String deviceId) {
        return "BeSafe.Device."
                + userId
                + "."
                + deviceId
                + ".PrivateKey.v1";
    }

    private static class StoredData {

        private final String userId;
        private final String deviceId;
        private final byte[] identityData;
        private final byte[] certificateData;

        public StoredData(
                String userId,
                String deviceId,
                byte[] identityData,
                byte[] certificateData
        ) {
            this.userId = userId;
            this.deviceId = deviceId;
            this.identityData = identityData;
            this.certificateData = certificateData;
        }

    }

}
