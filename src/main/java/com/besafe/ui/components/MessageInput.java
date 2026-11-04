package com.besafe.ui.components;

import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;

import java.util.function.Consumer;

public class MessageInput {

    private final HBox root;
    private final TextField txtMessage;
    private final Button btnSend;
    private Consumer<String> onSend;

    public MessageInput() {
        root = new HBox();
        txtMessage = new TextField();
        btnSend = new Button("➤");

        btnSend.setOnAction(event -> sendMessage());
        txtMessage.setOnAction(event -> sendMessage());

        root.getChildren().addAll(txtMessage, btnSend);
        root.setSpacing(8);
        HBox.setHgrow(txtMessage,  Priority.ALWAYS);
    }

    public void setOnSend(Consumer<String> onSend) {
        this.onSend = onSend;
    }

    private void sendMessage() {
        String message = txtMessage.getText();

        if (!message.isEmpty() && onSend != null) {
            onSend.accept(message);
            txtMessage.clear();
        }
    }

    public HBox getRoot() {
        return root;
    }

}
