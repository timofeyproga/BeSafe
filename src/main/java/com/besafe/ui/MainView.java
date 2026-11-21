package com.besafe.ui;

import com.besafe.conversation.Conversation;
import com.besafe.conversation.ConversationService;
import com.besafe.conversation.Message;
import com.besafe.core.BeSafeRuntime;
import com.besafe.identity.IdentityBackupService;
import com.besafe.network.PeerAddress;
import com.besafe.network.PeerConnection;
import com.besafe.protocol.IdentityPayload;
import com.besafe.protocol.ProtocolEvents;
import com.besafe.session.SessionManager;
import com.besafe.ui.components.ChatHeader;
import com.besafe.ui.components.ChatList;
import com.besafe.ui.components.MessageArea;
import com.besafe.ui.components.MessageInput;
import com.besafe.ui.dialogs.AddContactDialog;
import com.besafe.ui.dialogs.IdentityBackupDialog;
import com.besafe.ui.dialogs.TrustConnectionDialog;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class MainView implements ProtocolEvents {

    private final BeSafeRuntime runtime;
    private final ConversationService conversationService;

    private final Map<String, Conversation> conversationByUserId;
    private final Map<String, PeerConnection> connectionsByUserId = new HashMap<>();
    private final Map<String, String> peerIdByConversationId = new HashMap<>();

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
    private final IdentityBackupService backupService;

    public MainView(SessionManager sessionManager, BeSafeRuntime runtime, IdentityBackupService backupService) {
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
        this.backupService = backupService;
        conversationService = runtime.getConversationService();
        conversationByUserId = new HashMap<>();

        messageInput.setOnSend(content -> {
            if (selectedConversation == null) {
                return;
            }

            String peerId = peerIdByConversationId.get(selectedConversation.getId());

            if (peerId == null) {
                System.out.println("Peer ID not found");
                return;
            }

            PeerConnection connection = connectionsByUserId.get(peerId);

            if (connection == null) {
                new Alert(
                        Alert.AlertType.WARNING,
                        "The user is not connected."
                ).showAndWait();

                return;
            }

            try {
                runtime.sendMessage(connection, content);

                Message message = conversationService.sendMessage(
                        selectedConversation.getId(),
                        currentUserId,
                        content
                );

                messageArea.addMessage(content, true);
            } catch (Exception e) {
                new Alert(
                        Alert.AlertType.ERROR,
                        "Failed to send message: " + e.getMessage()
                ).showAndWait();

                e.printStackTrace();
            }
        });

        chatArea.setCenter(messageArea.getRoot());
        chatArea.setBottom(messageInput.getRoot());

        chatList.setOnChatSelected(userId -> {
            Conversation conversation = conversationByUserId.get(userId);

            if (conversation == null) {
                return;
            }

            selectedConversation = conversation;
            chatHeader.setUsername(conversation.getName());
            renderMessages(conversation);
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

        Label lblVersion = new Label("0.1.0-alpha-3");
        lblVersion.getStyleClass().add("lbl-version");

        VBox appBrand =  new VBox(lblBeSafe, lblVersion);
        appBrand.getStyleClass().add("app-brand");

        Button btnSetting = new Button("⚙");
        btnSetting.getStyleClass().add("settings-button");
        btnSetting.setOnAction(event -> {
            IdentityBackupDialog backupDialog = new IdentityBackupDialog(
                    backupService,
                    sessionManager.getUser(),
                    root.getScene().getWindow()
            );

            backupDialog.show();
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
        btnAddPrivate.setOnAction(event -> showAddPrivateChat());
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

        if (currentUserId.equals(peerId)) {
            showIdentityError("You cannot connect to yourself");
            runtime.disconnect(connection);
            return;
        }

        String fingerprint;

        try {
            fingerprint = calculateFingerprint(
                    remoteIdentity.getPublicKey()
            );
        } catch (Exception e) {
            showIdentityError("Could not calculate fingerprint", e);
            runtime.disconnect(connection);
            return;
        }

        boolean trusted = TrustConnectionDialog.showAndWait(
                root.getScene().getWindow(),
                username,
                peerId,
                fingerprint
        );

        if (!trusted) {
            try {
                runtime.rejectConnection(connection);
            } catch (Exception e) {
                runtime.disconnect(connection);
                System.err.println("Failed to reject connection: " + e.getMessage());
            }
            return;
        }

        try {
            runtime.trustConnection(connection);
            System.out.println("Trusted peer: " + username);
        } catch (Exception e) {
            showIdentityError("Failed to trust peer", e);
            runtime.disconnect(connection);
        }
    }

    @Override
    public void onMessageReceived(
            PeerConnection connection,
            IdentityPayload identity,
            String content
    ) {
        String username = identity.getUsername();
        String peerId = identity.getUserId();

        Conversation conversation = conversationByUserId.get(peerId);

        if (conversation == null) {
            System.err.println(
                    "Received message without an existing conversation: "
                            + username
            );
            return;
        }

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
        connectionsByUserId.values().removeIf(
                activeConnection -> activeConnection == connection
        );

        System.out.println("Peer disconnected");
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

    @Override
    public void onTrustEstablished(
            PeerConnection connection,
            IdentityPayload remoteIdentity
    ) {
        String username = remoteIdentity.getUsername();
        String peerId = remoteIdentity.getUserId();

        PeerConnection existing = connectionsByUserId.putIfAbsent(
                peerId,
                connection
        );

        if (existing != null && existing != connection) {
            System.out.println("Duplicate connection rejected: " + username);
            runtime.disconnect(connection);
            return;
        }

        try {
            connectionsByUserId.put(peerId, connection);

            Conversation conversation = getOrCreateConversation(username, peerId);

            if (conversation == null) {
                throw new IllegalStateException("Failed to get conversation");
            }

            System.out.println("Mutual trust established: " + username);
        } catch (Exception e) {
            connectionsByUserId.remove(peerId, connection);

            showIdentityError("Failed to establish conversation", e);

            runtime.disconnect(connection);
        }
    }

    private Conversation getOrCreateConversation(
            String username,
            String peerId
    ) {
        Conversation conversation = conversationByUserId.get(peerId);

        if (conversation != null) {
            peerIdByConversationId.put(conversation.getId(), peerId);
            return conversation;
        }

        try {
            conversation = conversationService.createPrivateConversation(
                    currentUserId,
                    peerId
            );

            if (conversation == null) {
                throw new IllegalStateException(
                        "ConversationService returned null"
                );
            }

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Could not create private conversation",
                    e
            );
        }

        conversationByUserId.put(peerId, conversation);
        peerIdByConversationId.put(conversation.getId(), peerId);

        chatList.addChat(peerId, username);

        return conversation;
    }

    private void showAddPrivateChat() {
        AddContactDialog.showAndWait(root.getScene().getWindow())
                .ifPresent(address -> {
                    try {
                        PeerConnection connection = runtime.connect(address);
                    } catch (Exception e) {
                        Alert alert = new Alert(Alert.AlertType.ERROR);
                        alert.setTitle("BeSafe");
                        alert.setHeaderText("Connection failed");
                        alert.setContentText(e.getMessage());
                        alert.showAndWait();
                    }
                });
    }

    private String calculateFingerprint(java.security.PublicKey publicKey)
            throws java.security.GeneralSecurityException {

        java.security.MessageDigest digest =
                java.security.MessageDigest.getInstance("SHA-256");

        byte[] hash = digest.digest(publicKey.getEncoded());

        return java.util.HexFormat.ofDelimiter(":")
                .withUpperCase()
                .formatHex(hash);
    }

    private void showIdentityError(
            String title,
            Exception e
    ) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("BeSafe");
        alert.setHeaderText(title);
        alert.setContentText(e.getMessage());
        alert.show();
    }

    private void showIdentityError(
            String e
    ) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("BeSafe");
        alert.setHeaderText("Connection failed");
        alert.setContentText(e);
        alert.show();
    }

    private void renderMessages(Conversation conversation) {
        messageArea.clearMessages();

        for (Message message : conversation.getMessages()) {
            boolean ownMessage = message.getSenderId().equals(currentUserId);

            messageArea.addMessage(
                    message.getContent(),
                    ownMessage
            );
        }
    }

}
