package com.besafe.protocol;

import com.besafe.core.RegistrationService;
import com.besafe.identity.UserIdentity;

public class HandshakeSecurityTest {

    public static void main(String[] args) throws Exception {

        testForgedSignature();
        testWrongMessageOrder();
        testModifiedTranscript();

        System.out.println();
        System.out.println("ALL SECURITY TESTS PASSED!");
    }

    // Тест 1: подделанная подпись Bob
    private static void testForgedSignature() throws Exception {

        Scenario scenario = createScenario();

        ProtocolMessage challenge = scenario.aliceHandshake.start();

        ProtocolMessage response =
                scenario.bobHandshake.receiveChallenge(challenge);

        // Изменяем последний байт подписи Bob
        byte[] payload = response.getPayload();
        payload[payload.length - 1] ^= 1;

        ProtocolMessage forgedResponse = new ProtocolMessage(
                MessageType.CHALLENGE_RESPONSE,
                payload
        );

        boolean rejected = false;

        try {
            scenario.aliceHandshake.receiveChallengeResponse(
                    forgedResponse
            );
        } catch (IllegalStateException exception) {
            rejected = true;
        }

        if (!rejected
                || scenario.aliceState.getStatus()
                != HandshakeStatus.FAILED) {
            throw new AssertionError(
                    "Forged signature was not rejected!"
            );
        }

        System.out.println("Forged signature: REJECTED");
    }

    // Тест 2: сообщение пришло не в том порядке
    private static void testWrongMessageOrder() throws Exception {

        Scenario scenario = createScenario();

        ProtocolMessage signature = new ProtocolMessage(
                MessageType.AUTHENTICATION_SIGNATURE,
                new byte[64]
        );

        boolean rejected = false;

        try {
            scenario.bobHandshake.receiveAuthenticationSignature(
                    signature
            );
        } catch (IllegalStateException exception) {
            rejected = true;
        }

        if (!rejected
                || scenario.bobState.getStatus()
                != HandshakeStatus.FAILED) {
            throw new AssertionError(
                    "Wrong message order was not rejected!"
            );
        }

        System.out.println("Wrong message order: REJECTED");
    }

    // Тест 3: изменённый transcript
    private static void testModifiedTranscript() throws Exception {

        Scenario scenario = createScenario();

        ProtocolMessage challenge = scenario.aliceHandshake.start();

        // Изменяем nonce Alice по пути к Bob
        byte[] modifiedNonce = challenge.getPayload();
        modifiedNonce[0] ^= 1;

        ProtocolMessage modifiedChallenge = new ProtocolMessage(
                MessageType.CHALLENGE,
                modifiedNonce
        );

        // Bob подписывает transcript с изменённым nonce
        ProtocolMessage response =
                scenario.bobHandshake.receiveChallenge(
                        modifiedChallenge
                );

        // Alice использует свой исходный nonce
        boolean rejected = false;

        try {
            scenario.aliceHandshake.receiveChallengeResponse(
                    response
            );
        } catch (IllegalStateException exception) {
            rejected = true;
        }

        if (!rejected
                || scenario.aliceState.getStatus()
                != HandshakeStatus.FAILED) {
            throw new AssertionError(
                    "Modified transcript was not rejected!"
            );
        }

        System.out.println("Modified transcript: REJECTED");
    }

    private static Scenario createScenario() throws Exception {

        RegistrationService registrationService =
                new RegistrationService();

        UserIdentity alice =
                registrationService.createUser("Alice");

        UserIdentity bob =
                registrationService.createUser("Bob");

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

        return new Scenario(
                aliceState,
                bobState,
                aliceHandshake,
                bobHandshake
        );
    }

    private record Scenario(
            HandshakeState aliceState,
            HandshakeState bobState,
            HandshakeService aliceHandshake,
            HandshakeService bobHandshake
    ) {}
}
