package com.besafe.protocol;

public enum HandshakeStatus {

    INITIAL,
    IDENTITY_EXCHANGED,
    CHALLENGE_SENT,
    CHALLENGE_RECEIVED,
    RESPONSE_SENT,
    AUTHENTICATED,
    FAILED

}
