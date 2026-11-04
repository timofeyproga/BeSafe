package com.besafe.network;

import com.besafe.core.RegistrationService;
import com.besafe.identity.UserIdentity;
import com.besafe.protocol.*;

import java.util.concurrent.atomic.AtomicReference;

public class HandshakeNetworkTest {

    private static final int PORT = 5051;

    public static void main(String[] args) throws Exception {

        RegistrationService registrationService =
                new RegistrationService();

        UserIdentity alice =
                registrationService.createUser("Alice");

        UserIdentity bob =
                registrationService.createUser("Bob");

        AtomicReference<Throwable> serverError =
                new AtomicReference<>();

        PeerServer server = new PeerServer(PORT);

        Thread serverThread = new Thread(() -> {
            try {
                runBob(server, bob);
            } catch (Throwable exception) {
                serverError.set(exception);
                exception.printStackTrace();
            }
        });

        serverThread.start();

        try {
            PeerClient client =
                    new PeerClient("127.0.0.1", PORT);

            try (PeerConnection connection = client.connect()) {

                ProtocolConnection protocol =
                        new ProtocolConnection(connection);

                IdentityPayloadSerializer serializer =
                        new IdentityPayloadSerializer();

                IdentityPayload alicePayload = createPayload(alice);

                // Проверяем сериализацию Alice локально
                byte[] identityBytes =
                        serializer.serialize(alicePayload);

                System.out.println(
                        "[ALICE] Payload size: " + identityBytes.length
                );

                serializer.deserialize(identityBytes);

                System.out.println(
                        "[ALICE] Local serialization: SUCCESS"
                );

                // Отправляем личность Alice
                protocol.send(new ProtocolMessage(
                        MessageType.IDENTITY_REQUEST,
                        identityBytes
                ));

                // Получаем личность Bob
                ProtocolMessage identityResponse =
                        protocol.receive();

                if (identityResponse.getType()
                        != MessageType.IDENTITY_RESPONSE) {
                    throw new IllegalStateException(
                            "Expected IDENTITY_RESPONSE"
                    );
                }

                IdentityPayload bobPayload =
                        serializer.deserialize(
                                identityResponse.getPayload()
                        );

                System.out.println(
                        "[ALICE] Bob identity received"
                );

                HandshakeState aliceState =
                        new HandshakeState(HandshakeRole.INITIATOR);

                aliceState.setRemoteIdentity(bobPayload);
                aliceState.setStatus(
                        HandshakeStatus.IDENTITY_EXCHANGED
                );

                HandshakeService aliceHandshake =
                        new HandshakeService(
                                alice,
                                aliceState,
                                new ChallengeService(),
                                new HandshakeCrypto()
                        );

                protocol.send(aliceHandshake.start());

                ProtocolMessage challengeResponse =
                        protocol.receive();

                ProtocolMessage signature =
                        aliceHandshake.receiveChallengeResponse(
                                challengeResponse
                        );

                protocol.send(signature);

                ProtocolMessage finish = protocol.receive();

                aliceHandshake.receiveAuthenticationFinish(finish);

                System.out.println(
                        "[ALICE] Status: " + aliceState.getStatus()
                );
            }

            serverThread.join();

            if (serverError.get() != null) {
                throw new RuntimeException(
                        "Bob failed", serverError.get()
                );
            }

            System.out.println();
            System.out.println("NETWORK HANDSHAKE SUCCESS!");

        } finally {
            server.close();
        }
    }

    private static void runBob(
            PeerServer server,
            UserIdentity bob
    ) throws Exception {

        try (PeerConnection connection =
                     server.acceptConnection()) {

            System.out.println("[BOB] Client connected");

            ProtocolConnection protocol =
                    new ProtocolConnection(connection);

            IdentityPayloadSerializer serializer =
                    new IdentityPayloadSerializer();

            ProtocolMessage identityRequest =
                    protocol.receive();

            System.out.println(
                    "[BOB] Received message: "
                            + identityRequest.getType()
            );

            byte[] receivedPayload =
                    identityRequest.getPayload();

            System.out.println(
                    "[BOB] Payload size: "
                            + receivedPayload.length
            );

            System.out.println(
                    "[BOB] First bytes: "
                            + java.util.HexFormat.of().formatHex(
                            receivedPayload,
                            0,
                            Math.min(12, receivedPayload.length)
                    )
            );

            if (identityRequest.getType()
                    != MessageType.IDENTITY_REQUEST) {
                throw new IllegalStateException(
                        "Expected IDENTITY_REQUEST"
                );
            }

            IdentityPayload alicePayload =
                    serializer.deserialize(receivedPayload);

            System.out.println(
                    "[BOB] Alice identity decoded"
            );

            IdentityPayload bobPayload = createPayload(bob);

            protocol.send(new ProtocolMessage(
                    MessageType.IDENTITY_RESPONSE,
                    serializer.serialize(bobPayload)
            ));

            System.out.println("[BOB] Identity response sent");

            HandshakeState bobState =
                    new HandshakeState(HandshakeRole.RESPONDER);

            bobState.setRemoteIdentity(alicePayload);
            bobState.setStatus(
                    HandshakeStatus.IDENTITY_EXCHANGED
            );

            HandshakeService bobHandshake =
                    new HandshakeService(
                            bob,
                            bobState,
                            new ChallengeService(),
                            new HandshakeCrypto()
                    );

            ProtocolMessage challenge = protocol.receive();

            ProtocolMessage response =
                    bobHandshake.receiveChallenge(challenge);

            protocol.send(response);

            ProtocolMessage signature = protocol.receive();

            ProtocolMessage finish =
                    bobHandshake.receiveAuthenticationSignature(
                            signature
                    );

            protocol.send(finish);

            System.out.println(
                    "[BOB] Status: " + bobState.getStatus()
            );
        }
    }

    private static IdentityPayload createPayload(
            UserIdentity identity
    ) {
        return new IdentityPayload(
                identity.getUserId(),
                identity.getUsername(),
                identity.getPublicKey()
        );
    }
}
