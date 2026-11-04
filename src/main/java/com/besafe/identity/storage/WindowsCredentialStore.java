package com.besafe.identity.storage;

import com.sun.jna.*;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.ptr.PointerByReference;

import java.io.IOException;

public class WindowsCredentialStore implements CredentialStore {

    private static final int CRED_TYPE_GENERIC = 1;
    private static final int CRED_PERSIST_LOCAL_MACHINE = 2;

    @Structure.FieldOrder({
            "Flags",
            "Type",
            "TargetName",
            "Comment",
            "LastWritten",
            "CredentialBlobSize",
            "CredentialBlob",
            "Persist",
            "AttributeCount",
            "Attributes",
            "TargetAlias",
            "UserName"
    })
    public static class Credential extends Structure {

        public int Flags;
        public int Type;
        public Pointer TargetName;
        public Pointer Comment;
        public WinBase.FILETIME LastWritten = new  WinBase.FILETIME();
        public int CredentialBlobSize;
        public Pointer CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public Pointer Attributes;
        public Pointer TargetAlias;
        public Pointer UserName;

        public Credential(Pointer pointer) {
            super(pointer);
        }

        public Credential() {
            super();
        }

    }

    @Override
    public void saveSecret(String key, byte[] secret) throws IOException {
        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException("Key cannot be null or blank");
        }

        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("Secret cannot be empty");
        }

        Memory targetName = new Memory(
                (key.length() + 1L) * Native.WCHAR_SIZE
        );

        Memory blob = new Memory(secret.length);

        try {
            targetName.setWideString(0, key);
            blob.write(0, secret, 0, secret.length);

            Credential credential = new Credential();

            credential.Type = CRED_TYPE_GENERIC;
            credential.TargetName = targetName;
            credential.CredentialBlobSize = secret.length;
            credential.CredentialBlob = blob;
            credential.Persist = CRED_PERSIST_LOCAL_MACHINE;

            credential.write();

            boolean success = WindowsCredentialApi.INSTANCE.CredWriteW(
                    credential.getPointer(),
                    0
            );

            if (!success) {
                throw new IOException("Failed to write credential: " + Native.getLastError());
            }
        } finally {
            blob.clear();
            targetName.clear();
        }
    }

    @Override
    public byte[] loadSecret(String key) throws IOException {
        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException("Key cannot be null or blank");
        }

        PointerByReference credenrialReference = new PointerByReference();

        boolean success = WindowsCredentialApi.INSTANCE.CredReadW(
                new WString(key),
                CRED_TYPE_GENERIC,
                0,
                credenrialReference
        );

        if (!success) {
            throw new IOException("Failed to read credential: " + Native.getLastError());
        }
        
        Pointer credenrialPointer = credenrialReference.getValue();

        if (credenrialPointer == null) {
            throw new IOException("Windows returned an empty credential");
        }

        try {
            Credential credential = new Credential(credenrialPointer);
            credential.read();

            if (credential.CredentialBlob == null
            || credential.CredentialBlobSize <= 0) {
                throw new IOException("Stored credential is empty");
            }

            return credential.CredentialBlob.getByteArray(
                    0,
                    credential.CredentialBlobSize
            );

        } finally {
            WindowsCredentialApi.INSTANCE.CredFree(credenrialPointer);
        }
    }

}
