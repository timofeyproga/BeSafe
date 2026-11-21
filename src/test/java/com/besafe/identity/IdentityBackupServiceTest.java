package com.besafe.identity;

import com.besafe.core.RegistrationService;
import com.besafe.identity.storage.IdentityEncryption;
import com.besafe.identity.storage.IdentitySerializer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class IdentityBackupServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void shouldCreateAndRestoreBackup() throws Exception {
        UserIdentity original =
                new RegistrationService().createUser("test");

        Path backupFile = tempDir.resolve("identity.bak");

        IdentityBackupService service = new IdentityBackupService(
                new IdentitySerializer(),
                new IdentityEncryption(),
                new IdentityValidator()
        );

        String recoveryCode =
                service.createBackup(original, backupFile);

        assertTrue(Files.exists(backupFile));
        assertTrue(recoveryCode.matches("[0-9a-f]{64}"));

        UserIdentity restored = service.restoreBackup(backupFile, recoveryCode);

        assertEquals(original.getUserId(), restored.getUserId());
        assertEquals(original.getUsername(), restored.getUsername());
    }

    @Test
    void shouldRejectIncorrectRecoveryCode() throws Exception {
        UserIdentity original =
                new RegistrationService().createUser("test");

        Path backupFile = tempDir.resolve("identity.bak");

        IdentityBackupService service = new IdentityBackupService(
                new IdentitySerializer(),
                new IdentityEncryption(),
                new IdentityValidator()
        );

        String recoveryCode =
                service.createBackup(original, backupFile);

        char replacement = recoveryCode.charAt(0) == '0' ? '1' : '0';

        String incorrectCode = replacement + recoveryCode.substring(1);

        assertThrows(
                Exception.class,
                () -> service.restoreBackup(backupFile, incorrectCode)
        );
    }

    @Test
    void shouldRejectCorruptedBackup() throws Exception {
        UserIdentity original =
                new RegistrationService().createUser("test");

        Path backupFile = tempDir.resolve("identity.bak");

        IdentityBackupService service = new IdentityBackupService(
                new IdentitySerializer(),
                new IdentityEncryption(),
                new IdentityValidator()
        );

        String recoveryCode =
                service.createBackup(original, backupFile);

        Files.write(backupFile, new byte[] {
                1, 2, 3, 4, 5
        });

        assertThrows(Exception.class,
                () -> service.restoreBackup(backupFile, "0".repeat(64)));
    }

}
