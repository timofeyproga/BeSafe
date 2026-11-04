package com.besafe.conversation;

import java.util.ArrayList;
import java.util.List;

public class Conversation {

    private final String id;
    private List<String> participants;
    private String name;
    private final ConversationType type;
    private List<Message> messages;

    public Conversation(
            String id,
            List<String> participants,
            String name,
            ConversationType type,
            List<Message> messages
    ) {
        this.id = id;
        this.participants = participants;
        this.name = name;
        this.type = type;
        this.messages = new ArrayList<>(messages);
    }

    public String getId() {
        return id;
    }

    public void addUser(String participant) {
        this.participants.add(participant);
    }

    public List<String> getUsers() {
        return this.participants;
    }

    public void removeUser(String participant) {
        this.participants.remove(participant);
    }

    public void rename(String newName) {
        this.name = newName;
    }

    public String getName() {
        return name;
    }

    public ConversationType getType() {
        return type;
    }

    public void addMessage(Message message) {
        this.messages.add(message);
    }

    public List<Message> getMessages() {
        return List.copyOf(this.messages);
    }

    public void removeMessage(Message message) {
        this.messages.remove(message);
    }

    public void deleteMessage(String messageId, String requestId) {
        Message message = null;

        for (Message convMessage : this.messages) {
            if (convMessage.getId().equals(messageId)) {
                message = convMessage;
                break;
            }
        }

        if (message == null) {
            throw new IllegalArgumentException("Message does not exist");
        }

        if (!message.getSenderId().equals(requestId)) {
            throw new IllegalArgumentException("Message's sender does not requester");
        }

        this.messages.remove(message);
    }

}
