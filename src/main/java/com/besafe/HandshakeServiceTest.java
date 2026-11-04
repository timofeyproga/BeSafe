package com.besafe;

import com.besafe.core.RegistrationService;
import com.besafe.identity.UserIdentity;
import com.besafe.protocol.*;

public class HandshakeServiceTest {

    public static void main(String[] args) throws Exception {

        RegistrationService registrationService =
                new RegistrationService();

        UserIdentity alice = registrationService.createUser("Alice");
        UserIdentity bob = registrationService.createUser("Bob");

        HandshakeState aliceState =
                new HandshakeState(HandshakeRole.INITIATOR);

        HandshakeState bobState =
                new HandshakeState(HandshakeRole.RESPONDER);

        IdentityPayload alicePayload = new IdentityPayload(
                alice.getUserId(),
                alice.getUsername(),
                alice.getPublicKey()
        );

        IdentityPayload bobPayload = new IdentityPayload(
                bob.getUserId(),
                bob.getUsername(),
                bob.getPublicKey()
        );

        aliceState.setRemoteIdentity(bobPayload);
        bobState.setRemoteIdentity(alicePayload);

        aliceState.setStatus(HandshakeStatus.IDENTITY_EXCHANGED);
        bobState.setStatus(HandshakeStatus.IDENTITY_EXCHANGED);

        ChallengeService challengeService = new ChallengeService();
        HandshakeCrypto crypto = new HandshakeCrypto();

        HandshakeService aliceHandshake = new HandshakeService(
                alice, aliceState, challengeService, crypto
        );

        HandshakeService bobHandshake = new HandshakeService(
                bob, bobState, challengeService, crypto
        );

        ProtocolMessage challenge = aliceHandshake.start();

        System.out.println("Alice sent challenge");

        ProtocolMessage challengeResponse =
                bobHandshake.receiveChallenge(challenge);

        System.out.println("Bob sent challenge response");

        ProtocolMessage aliceSignature =
                aliceHandshake.receiveChallengeResponse(
                        challengeResponse
                );

        System.out.println("Alice sent authentication signature");

        ProtocolMessage finish =
                bobHandshake.receiveAuthenticationSignature(
                        aliceSignature
                );

        System.out.println("Bob authenticated Alice");

        aliceHandshake.receiveAuthenticationFinish(finish);

        System.out.println("Alice authenticated Bob");

        System.out.println();
        System.out.println("Alice status: " + aliceState.getStatus());
        System.out.println("Bob status: " + bobState.getStatus());

        if (aliceState.getStatus() != HandshakeStatus.AUTHENTICATED
                || bobState.getStatus() != HandshakeStatus.AUTHENTICATED) {
            throw new AssertionError("Handshake failed!");
        }

        System.out.println();
        System.out.println("HANDSHAKE SUCCESS!");
    }
}
