package com.besafe.identity;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

public class IdentityValidatorTest {

    private final IdentityKeyManager keyManager =  new IdentityKeyManager();
    private final IdentityValidator validator = new IdentityValidator();

    @Test
    void shouldAcceptValidIdentity() throws Exception {
        KeyPair keyPair = keyManager.generateKeyPair();

        String userId = keyManager.generateUserId(
                keyPair.getPublic()
        );

        UserIdentity identity = new UserIdentity(
                "test",
                userId,
                keyPair.getPublic(),
                keyPair.getPrivate()
        );

        assertDoesNotThrow(() -> validator.validate(identity));

    }

    @Test
    void shouldRejectMismatchedKeys() throws Exception {
        KeyPair firstPair = keyManager.generateKeyPair();
        KeyPair secondPair = keyManager.generateKeyPair();

        String userId = keyManager.generateUserId(
                firstPair.getPublic()
        );

        assertThrows(
                Exception.class,
                () -> validator.validate(
                        firstPair.getPublic(),
                        secondPair.getPrivate(),
                        userId
                )
        );
    }

    @Test
    void shouldRejectIncorrectUserId() throws Exception {
        KeyPair keyPair = keyManager.generateKeyPair();

        assertThrows(
                Exception.class,
                () -> validator.validate(
                        keyPair.getPublic(),
                        keyPair.getPrivate(),
                        "not-user-id"
                )
        );
    }

}
