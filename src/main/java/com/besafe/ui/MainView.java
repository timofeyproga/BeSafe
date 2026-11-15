package com.besafe.ui;

import com.besafe.conversation.Conversation;
import com.besafe.conversation.ConversationService;
import com.besafe.conversation.Message;
import com.besafe.core.BeSafeRuntime;
import com.besafe.network.PeerConnection;
import com.besafe.protocol.IdentityPayload;
import com.besafe.protocol.ProtocolEvents;
import com.besafe.session.SessionManager;
import com.besafe.ui.components.ChatHeader;
import com.besafe.ui.components.ChatList;
import com.besafe.ui.components.MessageArea;
import com.besafe.ui.components.MessageInput;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.*;

import java.util.HashMap;
import java.util.Map;

public class MainView implements ProtocolEvents {

    private final BeSafeRuntime runtime;
    private final ConversationService conversationService;
    private final Map<String, Conversation> conversationByUsername;
    private Conversation selectedConversation;

    private final String currentUserId;

    private final BorderPane root;
    private final VBox sidebar;
    private final StackPane topBar;
    private final HBox actionBar;
    private final BorderPane chatArea;
    private final ChatList chatList;
    private final ChatHeader chatHeader;
    private final MessageArea messageArea;
    private final MessageInput messageInput;

    public MainView(SessionManager sessionManager, BeSafeRuntime runtime) {
        root = new BorderPane();
        sidebar = new VBox();
        topBar = new StackPane();
        actionBar = new HBox();
        chatArea = new BorderPane();
        chatList = new ChatList();
        chatHeader = new ChatHeader("Select a chat");
        messageArea = new MessageArea();
        messageInput = new MessageInput();

        currentUserId = sessionManager.getUser().getUserId();

        root.getStyleClass().add("app-root");
        sidebar.getStyleClass().add("sidebar");
        topBar.getStyleClass().add("app-top-bar");
        actionBar.getStyleClass().add("chat-action-bar");
        chatArea.getStyleClass().add("chat-area");

        this.runtime = runtime;
        conversationService = runtime.getConversationService();
        conversationByUsername = new HashMap<>();

        messageInput.setOnSend(content -> {
            if (selectedConversation == null) {
                return;
            }

            Message message = conversationService.sendMessage(
                    selectedConversation.getId(),
                    currentUserId,
                    content
            );

            messageArea.addMessage(message.getContent(), true);
        });

        chatArea.setCenter(messageArea.getRoot());
        chatArea.setBottom(messageInput.getRoot());

        chatList.setOnChatSelected(username -> {
            selectedConversation = conversationByUsername.get(username);

            if (selectedConversation == null) {
                System.out.println("Conversation is null");
                return;
            }

            chatHeader.setUsername(username);
            messageArea.clearMessages();

            for (Message message : selectedConversation.getMessages()) {
                boolean ownMessage = message.getSenderId().equals(currentUserId);

                messageArea.addMessage(message.getContent(), ownMessage);
            }
        });

        sidebar.setPrefWidth(260);

        root.setTop(topBar);
        root.setLeft(sidebar);
        root.setCenter(chatArea);

        sidebar.setSpacing(10);
        actionBar.setSpacing(8);

        sidebar.setPadding(new Insets(12));

        Label lblBeSafe = new Label("BeSafe");
        lblBeSafe.getStyleClass().add("app-title");

        Label lblVersion = new Label("0.0.5");
        lblVersion.getStyleClass().add("lbl-version");

        VBox appBrand =  new VBox(lblBeSafe, lblVersion);
        appBrand.getStyleClass().add("app-brand");

        Button btnSetting = new Button("⚙");
        btnSetting.getStyleClass().add("settings-button");
        btnSetting.setOnAction(event -> {
            javafx.scene.control.Alert alert =
                    new javafx.scene.control.Alert(
                            javafx.scene.control.Alert.AlertType.INFORMATION
                    );

            alert.setTitle("BeSafe");
            alert.setHeaderText("Settings");
            alert.setContentText("Settings will be available soon.");
            alert.showAndWait();
        });

        topBar.getChildren().addAll(appBrand, btnSetting, chatHeader.getRoot());

        StackPane.setAlignment(appBrand, Pos.CENTER_LEFT);
        StackPane.setAlignment(btnSetting, Pos.CENTER);
        StackPane.setAlignment(chatHeader.getRoot(), Pos.CENTER_RIGHT);

        appBrand.setMaxWidth(Region.USE_PREF_SIZE);

        chatHeader.getRoot().setMinWidth(Region.USE_PREF_SIZE);
        chatHeader.getRoot().setMaxWidth(Region.USE_PREF_SIZE);

        topBar.setPrefHeight(72);

        Button btnAddPrivate = new Button("+");
        btnAddPrivate.getStyleClass().add("chat-action-button");

        Button btnAddGroup = new Button("♟");
        btnAddGroup.getStyleClass().add("chat-action-button");

        Button btnAddChannel = new Button("▤");
        btnAddChannel.getStyleClass().add("chat-action-button");

        actionBar.getChildren().addAll(btnAddPrivate, btnAddGroup, btnAddChannel);

        sidebar.getChildren().addAll(actionBar, chatList.getRoot());
        VBox.setVgrow(chatList.getRoot(), Priority.ALWAYS);
    }

    public BorderPane getRoot() {
        return root;
    }

    @Override
    public void onAuthenticated(
            PeerConnection connection,
            IdentityPayload remoteIdentity
    ) {
        String username = remoteIdentity.getUsername();
        String peerId = remoteIdentity.getUserId();

        getOrCreateConversation(username, peerId);

        System.out.println("Authenticated: " + username);
    }

    @Override
    public void onMessageReceived(
            PeerConnection connection,
            IdentityPayload identity,
            String content
    ) {
        String username = identity.getUsername();
        String peerId = identity.getUserId();

        Conversation conversation = getOrCreateConversation(
                username,
                peerId
        );

        conversationService.sendMessage(
                conversation.getId(),
                peerId,
                content
        );

        if (selectedConversation != null
        && selectedConversation.getId().equals(conversation.getId())) {
            messageArea.addMessage(content, false);
        }

    }

    @Override
    public void onDisconnected(PeerConnection connection) {
        System.out.println("Disconnected: " + connection);
    }

    @Override
    public void onError(
            PeerConnection connection,
            String error
    ) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("BeSafe");
        alert.setHeaderText("Network error");
        alert.setContentText(error);
        alert.show();
    }

    private Conversation getOrCreateConversation(
            String username,
            String peerId
    ) {
        Conversation conversation = conversationByUsername.get(username);

        if (conversation != null) {
            return conversation;
        }

        try {
            conversation = conversationService.createPrivateConversation(
                    currentUserId,
                    peerId
            );
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        conversationByUsername.put(username, conversation);
        chatList.addChat(username);

        return conversation;
    }

}
