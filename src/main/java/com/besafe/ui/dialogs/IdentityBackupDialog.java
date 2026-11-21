package com.besafe.ui.dialogs;

import com.besafe.identity.IdentityBackupService;
import com.besafe.identity.UserIdentity;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.File;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class IdentityBackupDialog {

    private final IdentityBackupService backupService;
    private final UserIdentity identity;
    private final Window owner;

    public IdentityBackupDialog(
            IdentityBackupService backupService,
            UserIdentity identity,
            Window owner
    ) {
        this.backupService = backupService;
        this.identity = identity;
        this.owner = owner;
    }

    public void show() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save BeSafe identity backup");
        fileChooser.setInitialFileName("BeSafe-identity-backup.bsbackup");

        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter(
                        "BeSafe Backup (*.bsbackup)",
                        "*.bsbackup"
                )
        );

        File selectedFile = fileChooser.showSaveDialog(owner);

        if (selectedFile == null) {
            return;
        }

        Path destination = selectedFile.toPath().toAbsolutePath();
        Path tempFile = null;

        try {
            Path parent = destination.getParent();

            tempFile = Files.createTempFile(
                    parent,
                    "besafe-pending-",
                    ".tmp");

            String recoveryCode = backupService.createBackup(
                    identity,
                    tempFile
            );

            boolean confirmed = showRecoveryCode(recoveryCode);

            if (!confirmed) {
                return;
            }

            try {
                Files.move(
                        tempFile,
                        destination,
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE
                );
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(
                        tempFile,
                        destination,
                        StandardCopyOption.REPLACE_EXISTING
                );
            }

            Alert success = new Alert(Alert.AlertType.INFORMATION);
            success.initOwner(owner);
            success.setTitle("BeSafe");
            success.setHeaderText("Backup created successfully");
            success.setContentText("Your identity backup has been saved.");
            success.showAndWait();

        } catch (Exception e) {
            Alert error = new Alert(Alert.AlertType.ERROR);
            error.initOwner(owner);
            error.setTitle("BeSafe");
            error.setHeaderText("Backup creation failed");
            error.setContentText(e.getMessage());
            error.showAndWait();
        } finally {
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (Exception ignored) {
                }
            }
        }

    }

    private boolean showRecoveryCode(String recoveryCode) {
        Dialog<ButtonType> dialog = new Dialog<>();
        dialog.initOwner(owner);
        dialog.setTitle("Your Recovery Code");
        dialog.setHeaderText("Your identity backup has been created");

        ButtonType confirmButton = new ButtonType(
                "I've saved my Recovery Code",
                ButtonBar.ButtonData.OK_DONE
        );

        dialog.getDialogPane().getButtonTypes().addAll(
                confirmButton,
                ButtonType.CANCEL
        );

        Label description = new Label(
                "This code is required to restore your identity. "
                + "Keep it somewhere safe. BeSafe cannot recover it for you."
        );
        description.setWrapText(true);

        TextArea codeField = new TextArea(recoveryCode);
        codeField.setEditable(false);
        codeField.setWrapText(true);
        codeField.setPrefRowCount(3);

        Button copyButton = new Button("\uD83D\uDCCB");
        copyButton.setOnAction(event -> {
            ClipboardContent content = new ClipboardContent();
            content.putString(recoveryCode);
            Clipboard.getSystemClipboard().setContent(content);
        });

        CheckBox savedCheckBox = new CheckBox(
                "I have saved the Recovery Code in a safe place"
        );

        VBox content = new VBox(
                12,
                description,
                codeField,
                copyButton,
                savedCheckBox
        );
        content.setPadding(new Insets(10));
        content.setPrefWidth(430);

        dialog.getDialogPane().setContent(content);

        Button confirm = (Button) dialog.getDialogPane().lookupButton(confirmButton);
        confirm.disableProperty().bind(savedCheckBox.selectedProperty().not());

        return dialog.showAndWait()
                .filter(result -> result == confirmButton)
                .isPresent();
    }

}
