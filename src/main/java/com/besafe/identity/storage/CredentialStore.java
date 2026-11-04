package com.besafe.identity.storage;

import java.io.IOException;

public interface CredentialStore {

    void saveSecret(String key, byte[] secret) throws IOException;

    byte[] loadSecret(String key) throws IOException;

}
