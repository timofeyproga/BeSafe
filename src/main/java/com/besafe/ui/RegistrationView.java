package com.besafe.ui;

import com.besafe.core.RegistrationService;
import com.besafe.identity.IdentityStorage;
import com.besafe.identity.UserIdentity;
import com.besafe.session.SessionManager;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;

import java.security.NoSuchAlgorithmException;

public class RegistrationView {

    private final RegistrationService registrationService;
    private final SessionManager sessionManager;
    private final IdentityStorage identityStorage;
    private Runnable onRegisterComplete;

    public RegistrationView(
            RegistrationService registrationService,
            SessionManager sessionManager,
            IdentityStorage identityStorage
    ) {
        this.registrationService = registrationService;
        this.sessionManager = sessionManager;
        this.identityStorage = identityStorage;
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

        VBox vbox = new VBox(15);
        vbox.setPadding(new Insets(20));
        vbox.setAlignment(Pos.CENTER);
        vbox.getChildren().addAll(
                enterLabel,
                descLabel,
                txt,
                btnContinue
        );

        return vbox;

    }

    public void setOnRegisterComplete(Runnable callBack) {
        onRegisterComplete = callBack;
    }

}
