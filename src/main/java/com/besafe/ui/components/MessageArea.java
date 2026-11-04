package com.besafe.ui.components;

import javafx.application.Platform;
import javafx.scene.control.ScrollPane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

public class MessageArea {

    private final VBox root;
    private final VBox messages;
    private final ScrollPane scrollPane;

    public MessageArea() {
        root = new VBox();
        messages = new VBox();
        scrollPane = new ScrollPane();

        root.getStyleClass().add("message-area-panel");
        messages.getStyleClass().add("message-list");
        scrollPane.getStyleClass().add("message-scroll-pane");

        scrollPane.setContent(messages);
        scrollPane.setFitToWidth(true);
        scrollPane.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);
        root.getChildren().add(scrollPane);
        VBox.setVgrow(scrollPane, Priority.ALWAYS);
    }

    public void addMessage(String content, boolean ownMessage) {
        MessageBubble bubble = new MessageBubble(content, ownMessage);
        messages.getChildren().add(bubble.getRoot());
        Platform.runLater(() -> scrollPane.setVvalue(1.0));
    }

    public void clearMessages() {
        messages.getChildren().clear();
    }

    public VBox getRoot() {
        return root;
    }

}
