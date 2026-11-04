package com.besafe.ui.components;

import javafx.geometry.Pos;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;

public class MessageBubble {

    private final HBox root;
    private final Label lblContent;

    public MessageBubble(String content, boolean ownMessage) {
        root = new HBox();
        lblContent = new Label(content);
        lblContent.setWrapText(true);
        root.getChildren().add(lblContent);

        if (ownMessage) {
            root.setAlignment(Pos.CENTER_RIGHT);
        } else {
            root.setAlignment(Pos.CENTER_LEFT);
        }
    }

    public HBox getRoot() {
        return root;
    }

}
