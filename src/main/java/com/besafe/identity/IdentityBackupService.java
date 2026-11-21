package com.besafe.identity;

import com.besafe.identity.storage.IdentityEncryption;
import com.besafe.identity.storage.IdentitySerializer;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

public class IdentityBackupService {

    private static final int MAGIC = 0x4253424B;
    private static final int FORMAT_VERSION = 1;
    private static final int RECOVERY_CODE_LENGTH = 32;
    private static final int MIN_ECRYPTED_LENGTH = 28;
    private static final int MAX_BACKUP_SIZE = 1_048_576;

    private final IdentitySerializer serializer;
    private final IdentityEncryption encryption;
    private final IdentityValidator validator;

    private final SecureRandom secureRandom = new SecureRandom();

    public IdentityBackupService(
            IdentitySerializer serializer,
            IdentityEncryption encryption,
            IdentityValidator validator
    ) {
        this.serializer = serializer;
        this.encryption = encryption;
        this.validator = validator;
    }

    public String createBackup(
            UserIdentity user,
            Path backupFile
    ) throws Exception {

        validator.validate(user);

        byte[] recoveryKey = new byte[RECOVERY_CODE_LENGTH];
        secureRandom.nextBytes(recoveryKey);

        String recoveryCode = HexFormat.of().formatHex(recoveryKey);

        try {
            SecretKey secretKey = new SecretKeySpec(recoveryKey, "AES");

            byte[] serializedData = serializer.serialize(user);

            byte[] encryptedData = encryption.encrypt(serializedData, secretKey);

            byte[] backupData = createBackupFile(encryptedData);

            saveBackupFile(backupFile, backupData);

            return recoveryCode;
        } finally {
            Arrays.fill(recoveryKey, (byte) 0);
        }
    }

    public UserIdentity restoreBackup(
            Path backupFile,
            String recoveryCode
    ) throws Exception {

        byte[] recoveryKey;

        try {
            recoveryKey = HexFormat.of().parseHex(recoveryCode.trim());
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid recovery code format: " + e);
        }

        if (recoveryKey.length != RECOVERY_CODE_LENGTH) {
            Arrays.fill(recoveryKey, (byte) 0);
            throw new IOException("Invalid recovery code length: " + recoveryKey.length);
        }

        try {
            byte[] enctyptedData = readBackupFile(backupFile);

            SecretKey secretKey = new SecretKeySpec(recoveryKey, "AES");

            byte[] decryptedData = encryption.decrypt(enctyptedData, secretKey);

            UserIdentity identity = serializer.deserialize(decryptedData);

            validator.validate(identity);

            return identity;
        } finally {
            Arrays.fill(recoveryKey, (byte) 0);
        }
    }

    private byte[] createBackupFile(
            byte[] encryptedData
    ) throws IOException {

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        try (DataOutputStream out = new DataOutputStream(buffer)) {

            out.writeInt(MAGIC);
            out.writeInt(FORMAT_VERSION);
            out.writeInt(encryptedData.length);
            out.write(encryptedData);
        }

        return buffer.toByteArray();
    }

    private void saveBackupFile(
            Path backupFile,
            byte[] backupData
    ) throws IOException {

        Path absolutePath = backupFile.toAbsolutePath();
        Path parent = absolutePath.getParent();

        Files.createDirectories(parent);

        Path tempFile = Files.createTempFile(
                parent,
                "besafe-buckup",
                ".tmp"
        );

        try {
            Files.write(tempFile, backupData);

            try {
                Files.move(
                        tempFile,
                        absolutePath,
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE
                );
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(
                        tempFile,
                        absolutePath,
                        StandardCopyOption.REPLACE_EXISTING
                );
            }
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    private byte[] readBackupFile(
            Path backupFile
    ) throws IOException {

        long fileSize = Files.size(backupFile);

        if (fileSize > MAX_BACKUP_SIZE || fileSize < 12 + MIN_ECRYPTED_LENGTH) {
            throw new IOException("Invalid backup file size");
        }

        byte[] fileData = Files.readAllBytes(backupFile);

        try (DataInputStream in = new DataInputStream(
                new ByteArrayInputStream(fileData))) {

            int magic = in.readInt();
            int version = in.readInt();
            int encryptedLength = in.readInt();

            if (magic != MAGIC) {
                throw new IOException("Invalid backup file");
            }

            if (version != FORMAT_VERSION) {
                throw new IOException("Unsupported backup file version");
            }

            if (encryptedLength < MIN_ECRYPTED_LENGTH
                    || encryptedLength > MAX_BACKUP_SIZE) {
                throw new IOException("Invalid encrypted data length");
            }

            byte[] encryptedData = in.readNBytes(encryptedLength);

            if (encryptedData.length != encryptedLength) {
                throw new IOException("Incomplete backup file");
            }

            if (in.read() != -1) {
                throw new IOException("Unexpected data in backup file");
            }

            return encryptedData;
        }
    }

}
