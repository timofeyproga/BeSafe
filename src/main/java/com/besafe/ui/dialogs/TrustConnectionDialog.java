package com.besafe.ui.dialogs;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.Window;

public class TrustConnectionDialog {

    public static boolean showAndWait(
            Window owner,
            String username,
            String peerId,
            String fingerprint
    ) {
        Stage stage = new Stage();

        stage.setTitle("BeSafe - Connection Request");
        stage.setResizable(false);

        if (owner != null) {
            stage.initOwner(owner);
            stage.initModality(Modality.WINDOW_MODAL);
        }

        Label title = new Label("Trust this connection?");
        title.getStyleClass().add("trust-title");

        Label description = new Label(
                "A BeSafe user is trying to establish a connection with you."
        );

        description.setWrapText(true);
        description.getStyleClass().add("trust-description");

        Label usernameLabel = new Label("USERNAME");
        Label usernameValue = new Label(username);

        Label idLabel = new Label("USER ID");
        Label idValue = new Label(peerId);
        idValue.setWrapText(true);

        Label fingerprintLabel = new Label("SECURITY FINGERPRINT");
        Label fingerprintValue = new Label(fingerprint);
        fingerprintValue.setWrapText(true);

        VBox identityCard = new VBox(
                7,
                usernameLabel,
                usernameValue,
                idLabel,
                idValue,
                fingerprintLabel,
                fingerprintValue
        );

        identityCard.getStyleClass().add("trust-identity-card");

        usernameLabel.getStyleClass().add("trust-field-label");
        idLabel.getStyleClass().add("trust-field-label");
        fingerprintLabel.getStyleClass().add("trust-field-label");

        usernameValue.getStyleClass().add("trust-field-value");
        idValue.getStyleClass().add("trust-field-value");
        fingerprintValue.getStyleClass().add("trust-field-value");

        Label warning = new Label(
                "Verify the fingerprint through a separate trusted channel."
        );
        warning.setWrapText(true);
        warning.getStyleClass().add("trust-warning");

        Button rejectButton = new Button("Reject");
        Button trustButton = new Button("Trust");

        rejectButton.getStyleClass().add("trust-reject-button");
        trustButton.getStyleClass().add("trust-accept-button");

        HBox buttons = new HBox(10, rejectButton, trustButton);
        buttons.setAlignment(Pos.CENTER_RIGHT);

        VBox content = new VBox(
                16,
                title,
                description,
                identityCard,
                warning,
                buttons
        );

        content.setPadding(new Insets(24));
        content.getStyleClass().add("trust-dialog-root");

        Scene scene = new Scene(content);

        if (owner != null && owner.getScene() != null) {
            scene.getStylesheets().addAll(owner.getScene().getStylesheets());
        }

        stage.setScene(scene);

        boolean[] accepted = {false};

        trustButton.setOnAction(event -> {
            accepted[0] = true;
            stage.close();
        });

        rejectButton.setOnAction(event -> {
            accepted[0] = false;
            stage.close();
        });

        stage.setOnCloseRequest(event -> accepted[0] = false);

        stage.showAndWait();

        return accepted[0];
    }

}
