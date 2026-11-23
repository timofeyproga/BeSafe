package com.besafe.identity;

import java.io.IOException;

public class IdentityCorruptedException extends IOException {

    public IdentityCorruptedException(String message, Throwable cause) {
        super(message, cause);
    }

}
