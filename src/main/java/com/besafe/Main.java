package com.besafe;

import com.besafe.core.RegistrationService;
import com.besafe.identity.IdentityStorage;
import com.besafe.identity.UserIdentity;
import com.besafe.identity.storage.CredentialStore;
import com.besafe.identity.storage.IdentityEncryption;
import com.besafe.identity.storage.IdentitySerializer;
import com.besafe.identity.storage.WindowsCredentialStore;
import com.besafe.session.SessionManager;
import com.besafe.ui.MainView;
import com.besafe.ui.RegistrationView;
import javafx.application.Application;
import javafx.scene.Parent;
import javafx.scene.control.Alert;
import javafx.stage.Stage;
import javafx.scene.Scene;

public class Main extends Application {

    @Override
    public void start(Stage stage) {

        RegistrationService registrationService = new RegistrationService();
        SessionManager sessionManager = new SessionManager();

        CredentialStore credentialStore = new WindowsCredentialStore();
        IdentitySerializer serializer = new IdentitySerializer();
        IdentityEncryption encryption = new IdentityEncryption();

        IdentityStorage identityStorage = new IdentityStorage(credentialStore, serializer, encryption);

        stage.setTitle("BeSafe");
        stage.setWidth(1000);
        stage.setHeight(650);

        try {
            identityStorage.initialize();

            UserIdentity user = identityStorage.load();

            Parent root;

            if (user == null) {
                RegistrationView registrationView = new RegistrationView(
                        registrationService,
                        sessionManager,
                        identityStorage
                );

                root = registrationView.createView();

                Scene scene = new Scene(root);

                registrationView.setOnRegisterComplete(() -> {
                    MainView mainView = new MainView(sessionManager);
                    scene.setRoot(mainView.getRoot());
                });

                scene.getStylesheets().add(getClass().getResource("/style.css").toExternalForm());

                stage.setScene(scene);
                stage.show();

                return;
            } else {
                sessionManager.setUser(user);

                MainView mainView = new MainView(sessionManager);

                root = mainView.getRoot();
            }

            Scene scene = new Scene(root);
            scene.getStylesheets().add(
                    getClass().getResource("/style.css").toExternalForm()
            );

            stage.setScene(scene);
            stage.show();

        } catch (Exception e) {
            e.printStackTrace();

            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("BeSafe");
            alert.setHeaderText("Failed to load user identity");
            alert.setContentText(e.getMessage());
            alert.showAndWait();
        }

    }

    public static void main(String[] args) throws InterruptedException {
        launch(args);
    }

}