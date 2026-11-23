package com.besafe.ui;

import com.besafe.core.RegistrationService;
import com.besafe.identity.IdentityBackupService;
import com.besafe.identity.IdentityStorage;
import com.besafe.identity.UserIdentity;
import com.besafe.session.SessionManager;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.File;
import java.security.NoSuchAlgorithmException;

public class RegistrationView {

    private final RegistrationService registrationService;
    private final SessionManager sessionManager;
    private final IdentityStorage identityStorage;
    private final IdentityBackupService backupService;

    private Runnable onRegisterComplete;

    public RegistrationView(
            RegistrationService registrationService,
            SessionManager sessionManager,
            IdentityStorage identityStorage,
            IdentityBackupService backupService
    ) {
        this.registrationService = registrationService;
        this.sessionManager = sessionManager;
        this.identityStorage = identityStorage;
        this.backupService = backupService;
    }

    public VBox createView() {

        Label enterLabel = new Label("Welcome to BeSafe!");
        enterLabel.setId("welcome-title");
        Label descLabel = new Label("Create your identity to get started");
        descLabel.setId("welcome-description");
        TextField txt = new TextField();
        txt.setId("name-field");
        Button btnContinue = new Button("Continue");
        btnContinue.setId("continue-button");

        btnContinue.setOnAction(e -> {
            String name = txt.getText();

            try {
                UserIdentity user = registrationService.createUser(name);
                identityStorage.save(user);
                sessionManager.setUser(user);

                if (onRegisterComplete != null) {
                    onRegisterComplete.run();
                }

            } catch (IllegalArgumentException ex) {
                Alert alert = new Alert(Alert.AlertType.WARNING);
                alert.setTitle("BeSafe");
                alert.setHeaderText("Registration failed!");
                alert.setContentText(ex.getMessage());
                alert.showAndWait();
            } catch (NoSuchAlgorithmException ex) {
                Alert alert = new Alert(Alert.AlertType.WARNING);
                alert.setTitle("BeSafe");
                alert.setHeaderText("Registration failed!");
                alert.setContentText(ex.getMessage());
                alert.showAndWait();
            } catch (Exception ex) {
                Alert alert = new Alert(Alert.AlertType.WARNING);
                alert.setTitle("BeSafe");
                alert.setHeaderText("Registration failed!");
                alert.setContentText(ex.getMessage());
                alert.showAndWait();
            }
        });

        Button btnRestore = new Button("Restore identity");
        btnRestore.setOnAction(event -> {
            Window owner = txt.getScene().getWindow();

            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("select BeSafe backup");

            fileChooser.getExtensionFilters().add(
                    new FileChooser.ExtensionFilter(
                            "BeSafe Backup (*.bsbackup)",
                            "*.bsbackup"
                    ));

            File backupFile = fileChooser.showOpenDialog(owner);

            if (backupFile == null) {
                return;
            }

            TextInputDialog codeDialog = new TextInputDialog();
            codeDialog.initOwner(owner);
            codeDialog.setTitle("Identity Recover");
            codeDialog.setHeaderText("Enter your Recovery Code");
            codeDialog.setContentText("Recovery Code: ");

            codeDialog.getEditor().setPromptText("64-character Recovery Code");

            codeDialog.getDialogPane().getStylesheets().addAll(
                    owner.getScene().getStylesheets()
            );
            codeDialog.getDialogPane().getStyleClass().add("besafe-dialog");

            String recoveryCode = codeDialog.showAndWait().orElse(null);

            if (recoveryCode == null || recoveryCode.isBlank()) {
                return;
            }

            try {
                UserIdentity restoredUser = backupService.restoreBackup(
                        backupFile.toPath(),
                        recoveryCode
                );

                identityStorage.save(restoredUser);

                sessionManager.setUser(restoredUser);

                Alert success = new Alert(Alert.AlertType.INFORMATION);
                success.initOwner(owner);
                success.setTitle("BeSafe");
                success.setHeaderText("Identity Recovered");
                success.setContentText(
                        "Your identity has been restored.\nUser ID:"
                            + restoredUser.getUserId()
                );

                success.getDialogPane().getStylesheets().addAll(
                        owner.getScene().getStylesheets()
                );
                success.getDialogPane().getStyleClass().add("besafe-dialog");

                success.showAndWait();

                if (onRegisterComplete != null) {
                    onRegisterComplete.run();
                }
            } catch (Exception e) {
                Alert error = new Alert(Alert.AlertType.ERROR);
                error.initOwner(owner);
                error.setTitle("BeSafe");
                error.setHeaderText("Identity recovery failed!");
                error.setContentText(
                        "Could not restore your identity. "
                        + "Check the backup file and Recovery Code. "
                        + "Error message: " + e.getMessage()
                );

                error.getDialogPane().getStylesheets().addAll(
                        owner.getScene().getStylesheets()
                );

                error.getDialogPane().getStyleClass().add("besafe-dialog");

                error.showAndWait();
            }
        });

        VBox vbox = new VBox(15);
        vbox.setPadding(new Insets(20));
        vbox.setAlignment(Pos.CENTER);
        vbox.getChildren().addAll(
                enterLabel,
                descLabel,
                txt,
                btnContinue,
                btnRestore
        );

        return vbox;

    }

    public void setOnRegisterComplete(Runnable callBack) {
        onRegisterComplete = callBack;
    }

}
