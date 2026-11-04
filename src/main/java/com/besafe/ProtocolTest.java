package com.besafe;

import com.besafe.protocol.MessageType;
import com.besafe.protocol.ProtocolMessage;
import com.besafe.protocol.ProtocolSerializer;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class ProtocolTest {

    public static void main(String[] args) throws Exception {

        String text = "Hello from BeSafe!";

        ProtocolMessage original = new ProtocolMessage(
                MessageType.CHAT_MESSAGE,
                text.getBytes(StandardCharsets.UTF_8)
        );

        byte[] serialized = ProtocolSerializer.serialize(original);

        ProtocolMessage restored = ProtocolSerializer.deserialize(serialized);
        String restoredText = new String(
                restored.getPayload(),
                StandardCharsets.UTF_8
        );

        System.out.println("Type: " + restored.getType());
        System.out.println("Message: " + restoredText);

        System.out.println(
                "Payload matches: " +
                        Arrays.equals(original.getPayload(), restored.getPayload())
        );

    }

}
