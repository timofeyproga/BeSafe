package com.besafe.conversation;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

public class ConversationService {

    private final Map<String, Conversation> conversations;

    public ConversationService() {
        this.conversations = new HashMap<>();
    }

    public Conversation getConversation(String id) {
        return conversations.get(id);
    }

    public List<Conversation> getAllConversations() {
        return List.copyOf(this.conversations.values());
    }

    public void deleteConversation(String id) {
        conversations.remove(id);
    }

    public Conversation createPrivateConversation(String firstUserId, String secondUserId) throws NoSuchAlgorithmException {
        if (firstUserId == null || secondUserId == null
        || firstUserId.isBlank() || secondUserId.isBlank()) {
            throw new IllegalArgumentException("User IDs cannot be null or blank");
        }

        if (firstUserId.equals(secondUserId)) {
            throw new IllegalArgumentException("The first and second user are the same");
        }

        String id = generatePrivateConversationId(firstUserId, secondUserId);

        Conversation existing = conversations.get(id);

        if (existing != null) {
            return existing;
        }

        Conversation conversation = new Conversation(
                id,
                List.of(firstUserId, secondUserId),
                "",
                ConversationType.PRIVATE,
                new ArrayList<>()
        );

        this.conversations.put(id, conversation);
        return conversation;
    }

    private String generatePrivateConversationId(String firstUserId, String secondUserId) throws NoSuchAlgorithmException {
        List<String> participants = new ArrayList<>(
                List.of(firstUserId, secondUserId)
        );

        Collections.sort(participants);

        String id = String.join("_", participants);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = id.getBytes(StandardCharsets.UTF_8);
        byte[] hash = digest.digest(bytes);

        return HexFormat.of().formatHex(hash);
    }

    public Message sendMessage(String conversationId, String senderId, String content) {
        if (content == null || content.isBlank()) {
            throw new IllegalArgumentException("Message cannot be null or blank");
        }

        Conversation conversation = getConversation(conversationId);

        if (conversation == null) {
            throw new IllegalArgumentException("The conversation does not exist");
        }

        if (!conversation.getUsers().contains(senderId)) {
            throw new IllegalArgumentException("Conversation does not contain sender");
        }

        Message message = new Message(
                UUID.randomUUID().toString(),
                senderId,
                content,
                System.currentTimeMillis()
        );

        conversation.addMessage(message);

        return message;
    }

    public void deleteMessage(String conversationId, String messageId, String requestId) {
        Conversation conversation = getConversation(conversationId);

        if (conversation == null) {
            throw new IllegalArgumentException("The conversation does not exist");
        }

        conversation.deleteMessage(
                messageId,
                requestId
        );
    }

}
