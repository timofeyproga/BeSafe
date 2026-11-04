
package com.besafe.ui.components;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;

public class ChatHeader {

    private final HBox root;
    private final Label avatar;
    private final Label lblUsername;

    public ChatHeader(String username) {
        root = new HBox();

        avatar = new Label("👤");
        lblUsername = new Label(username);

        root.getStyleClass().add("chat-header");
        avatar.getStyleClass().add("chat-header-avatar");
        lblUsername.getStyleClass().add("chat-header-username");

        root.setAlignment(Pos.CENTER_LEFT);
        root.setSpacing(12);
        root.setPadding(new Insets(12, 16, 12, 16));

        root.getChildren().addAll(avatar, lblUsername);
    }

    public void setUsername(String username) {
        lblUsername.setText(username);
    }

    public HBox getRoot() {
        return root;
    }
}
