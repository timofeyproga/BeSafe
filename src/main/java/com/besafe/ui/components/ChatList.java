
package com.besafe.ui.components;

import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

import java.util.function.Consumer;

public class ChatList {

    private final VBox root;
    private final VBox chatItems;
    private final ScrollPane scrollPane;

    private Consumer<String> onChatSelected;
    private VBox selectedChatItem;

    public ChatList() {
        root = new VBox();
        chatItems = new VBox();
        scrollPane = new ScrollPane();

        root.getStyleClass().add("chat-list-panel");
        chatItems.getStyleClass().add("chat-items");
        scrollPane.getStyleClass().add("chat-scroll-pane");

        scrollPane.setContent(chatItems);
        scrollPane.setFitToWidth(true);
        scrollPane.setPannable(true);

        scrollPane.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);
        scrollPane.setVbarPolicy(ScrollPane.ScrollBarPolicy.AS_NEEDED);

        root.getChildren().add(scrollPane);

        VBox.setVgrow(scrollPane, Priority.ALWAYS);
    }

    public void addChat(String username) {
        VBox chatItem = new VBox();
        HBox chatInfo = new HBox();

        Label avatar = new Label("👤");
        Label lblUsername = new Label(username);

        chatItem.getStyleClass().add("chat-item");
        chatInfo.getStyleClass().add("chat-info");
        avatar.getStyleClass().add("chat-avatar");
        lblUsername.getStyleClass().add("chat-username");

        chatInfo.getChildren().addAll(avatar, lblUsername);
        chatItem.getChildren().add(chatInfo);

        chatItem.setMaxWidth(Double.MAX_VALUE);

        chatItem.setOnMouseClicked(event -> {
            if (selectedChatItem != null) {
                selectedChatItem.getStyleClass().remove("selected");
            }

            chatItem.getStyleClass().add("selected");
            selectedChatItem = chatItem;

            if (onChatSelected != null) {
                onChatSelected.accept(username);
            }
        });

        chatItems.getChildren().add(chatItem);
    }

    public void setOnChatSelected(Consumer<String> onChatSelected) {
        this.onChatSelected = onChatSelected;
    }

    public VBox getRoot() {
        return root;
    }
}
