package com.besafe.identity.storage;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

public interface WindowsCredentialApi extends StdCallLibrary {

    WindowsCredentialApi INSTANCE = Native.load(
            "Advapi32",
            WindowsCredentialApi.class,
            W32APIOptions.UNICODE_OPTIONS
    );

    boolean CredWriteW(Pointer credential, int flags);

    boolean CredReadW(
            WString targetName,
            int type,
            int flags,
            PointerByReference credential
    );

    void CredFree(Pointer credential);

}
