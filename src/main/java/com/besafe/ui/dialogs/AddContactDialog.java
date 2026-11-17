
package com.besafe.ui.dialogs;

import com.besafe.network.PeerAddress;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.control.TextFormatter;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.Window;

import java.util.Optional;

public class AddContactDialog {

    public static Optional<PeerAddress> showAndWait(Window owner) {

        Stage stage = new Stage();

        stage.setTitle("BeSafe");
        stage.setResizable(false);

        if (owner != null) {
            stage.initOwner(owner);
            stage.initModality(Modality.WINDOW_MODAL);
        }

        TextField hostField = new TextField();
        hostField.setPromptText("192.168.1.100");

        TextField portField = new TextField("45821");

        portField.setTextFormatter(new TextFormatter<>(change ->
                change.getControlNewText().matches("\\d{0,5}")
                        ? change
                        : null
        ));

        Label errorLabel = new Label();
        errorLabel.getStyleClass().add("dialog-error");

        GridPane grid = new GridPane();
        grid.setHgap(12);
        grid.setVgap(12);

        grid.add(new Label("IP Address:"), 0, 0);
        grid.add(hostField, 1, 0);

        grid.add(new Label("Port:"), 0, 1);
        grid.add(portField, 1, 1);

        Button cancelButton = new Button("Cancel");
        Button connectButton = new Button("Connect");

        cancelButton.getStyleClass().add("dialog-secondary-button");
        connectButton.getStyleClass().add("dialog-primary-button");

        HBox buttons = new HBox(10, cancelButton, connectButton);
        buttons.setAlignment(Pos.CENTER_RIGHT);

        VBox root = new VBox(16, grid, errorLabel, buttons);
        root.setPadding(new Insets(20));
        root.getStyleClass().add("add-contact-root");

        Scene scene = new Scene(root);

        // Reuse the stylesheet from the main application.
        if (owner != null && owner.getScene() != null) {
            scene.getStylesheets().addAll(
                    owner.getScene().getStylesheets()
            );
        }

        stage.setScene(scene);

        PeerAddress[] result = new PeerAddress[1];

        cancelButton.setOnAction(event -> stage.close());

        connectButton.setOnAction(event -> {

            try {
                String host = hostField.getText().trim();
                String portText = portField.getText().trim();

                if (!isValidIpv4(host)) {
                    throw new IllegalArgumentException("Invalid IP address");
                }

                if (portText.isEmpty()) {
                    throw new IllegalArgumentException(
                            "Please enter a port."
                    );
                }

                int port = Integer.parseInt(portText);

                PeerAddress address = new PeerAddress(host, port);

                result[0] = address;
                stage.close();

            } catch (IllegalArgumentException e) {
                errorLabel.setText(e.getMessage());
            }
        });

        stage.setOnShown(event -> hostField.requestFocus());

        stage.showAndWait();

        return Optional.ofNullable(result[0]);
    }

    private static boolean isValidIpv4(String ip) {

        if (ip == null || ip.isBlank()) {
            return false;
        }

        String[] parts = ip.trim().split("\\.", -1);

        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (!part.matches("\\d{1,3}")) {
                return false;
            }

            int octet = Integer.parseInt(part);

            if (octet > 255) {
                return false;
            }
        }

        return true;
    }
}
