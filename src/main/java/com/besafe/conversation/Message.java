package com.besafe.conversation;

public class Message {

    private final String id;
    private final String senderId;
    private final String content;
    private final long timestamp;

    public Message(
            String id,
            String senderId,
            String content,
            long timestamp
    ) {
        this.id = id;
        this.senderId = senderId;
        this.content = content;
        this.timestamp = timestamp;
    }

    public String getId() {
        return id;
    }

    public String getSenderId() {
        return senderId;
    }

    public String getContent() {
        return content;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void delete() {
        // тоже не продумал еще и может тоже не понадобится для удаления сообщения
    }

}
