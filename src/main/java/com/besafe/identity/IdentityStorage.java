package com.besafe.identity;

import com.besafe.identity.storage.CredentialStore;
import com.besafe.identity.storage.IdentityEncryption;
import com.besafe.identity.storage.IdentitySerializer;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Path;
import java.nio.file.Files;
import java.io.IOException;
import java.nio.file.StandardCopyOption;

public class IdentityStorage {

    private final Path directory =
            Path.of(System.getProperty("user.home"), "BeSafe");

    private final Path identityFile =
            directory.resolve("identity.dat");

    private final CredentialStore credentialStore;
    private final IdentitySerializer serializer;
    private final IdentityEncryption encryption;

    private static final String ENCRYPTION_KEY_NAME =
            "BeSafe.IdentityEncryptionKey.v1";

    public IdentityStorage(
            CredentialStore credentialStore,
            IdentitySerializer serializer,
            IdentityEncryption encryption
    ) {
        this.credentialStore = credentialStore;
        this.serializer = serializer;
        this.encryption = encryption;
    }

    public void initialize() throws IOException {
        try {
            Files.createDirectories(directory);
        } catch (IOException exception) {
            throw new IOException(
                    "Failed to initialize BeSafe directory",
                    exception
            );
        }
    }

    public void save(UserIdentity user) throws Exception {
        initialize();

        SecretKey encryptionKey;

        if (Files.exists(identityFile)) {
            byte[] keyBytes = credentialStore.loadSecret(ENCRYPTION_KEY_NAME);
            encryptionKey = new SecretKeySpec(keyBytes, "AES");
        } else {
            encryptionKey = encryption.generateKey();

            credentialStore.saveSecret(
                    ENCRYPTION_KEY_NAME,
                    encryptionKey.getEncoded()
            );
        }

        byte[] serializedData = serializer.serialize(user);
        byte[] encryptedData = encryption.encrypt(serializedData, encryptionKey);

        Path tempFile = Files.createTempFile(
                directory,
                "identity-",
                ".tmp"
        );

        try {
            Files.write(tempFile, encryptedData);

            try {
                Files.move(
                        tempFile,
                        identityFile,
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE
                );
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(
                        tempFile,
                        identityFile,
                        StandardCopyOption.REPLACE_EXISTING
                );
            }
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    public UserIdentity load() throws Exception {
        if (!Files.exists(identityFile)) {
            return null;
        }

        byte[] encryptedData = Files.readAllBytes(identityFile);

        byte[] keyBytes = credentialStore.loadSecret(ENCRYPTION_KEY_NAME);

        if (keyBytes.length != 32) {
            throw new IOException("Invalid AES key length");
        }

        SecretKey encryptionKey = new SecretKeySpec(keyBytes, "AES");

        byte[] decryptedData = encryption.decrypt(
                encryptedData,
                encryptionKey
        );

        return serializer.deserialize(decryptedData);
    }

}
