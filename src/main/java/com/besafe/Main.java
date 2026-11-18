package com.besafe;

import com.besafe.conversation.Message;
import com.besafe.core.BeSafeRuntime;
import com.besafe.core.RegistrationService;
import com.besafe.identity.IdentityStorage;
import com.besafe.identity.UserIdentity;
import com.besafe.identity.storage.CredentialStore;
import com.besafe.identity.storage.IdentityEncryption;
import com.besafe.identity.storage.IdentitySerializer;
import com.besafe.identity.storage.WindowsCredentialStore;
import com.besafe.session.SessionManager;
import com.besafe.ui.JavaFxProtocolEvents;
import com.besafe.ui.MainView;
import com.besafe.ui.RegistrationView;

import javafx.application.Application;
import javafx.scene.Parent;
import javafx.scene.control.Alert;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import javafx.scene.Scene;

import java.io.IOException;
import java.util.Objects;

public class Main extends Application {

    private static final int DEFAULT_PORT = 45821;

    private BeSafeRuntime runtime;

    @Override
    public void start(Stage stage) {

        RegistrationService registrationService = new RegistrationService();
        SessionManager sessionManager = new SessionManager();

        CredentialStore credentialStore = new WindowsCredentialStore();
        IdentitySerializer serializer = new IdentitySerializer();
        IdentityEncryption encryption = new IdentityEncryption();

        IdentityStorage identityStorage = new IdentityStorage(credentialStore, serializer, encryption);

        Image logo = new Image(
                Objects.requireNonNull(
                        getClass().getResourceAsStream("/images/logo.png")
                )
        );

        stage.getIcons().add(logo);
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
                    try {
                        openMainView(stage, scene, sessionManager);
                    } catch (Exception e) {
                        showError("Failed to start BeSafe", e);
                    }
                });

                scene.getStylesheets().add(getClass().getResource("/style.css").toExternalForm());

                stage.setScene(scene);
                stage.show();

                return;
            }

            sessionManager.setUser(user);

            Scene scene = new Scene(new Parent() {});

            openMainView(stage, scene, sessionManager);

        } catch (Exception e) {
            showError("Failed to load user identity", e);
        }

    }

    private void openMainView(
            Stage stage,
            Scene scene,
            SessionManager sessionManager
    ) throws IOException {

        JavaFxProtocolEvents events =
                new JavaFxProtocolEvents();

        runtime = new BeSafeRuntime(
                sessionManager.getUser(),
                events
        );

        MainView mainView = new MainView(
                sessionManager,
                runtime
        );

        events.setListener(mainView);

        try {
            runtime.startServer(DEFAULT_PORT);

            System.out.println(
                    "BeSafe server started on port " + DEFAULT_PORT
            );
        } catch (IOException e) {
            showWarning(
                    "Could not start the server",
                    "BeSafe could not listen on port "
                        + DEFAULT_PORT
                        + ". Incoming connections will not work.\n"
                        + e.getMessage()
            );
        }

        scene.setRoot(mainView.getRoot());

        if (scene.getStylesheets().isEmpty()) {
            scene.getStylesheets().add(getClass().getResource("/style.css").toExternalForm());
        }

        stage.setScene(scene);

        stage.setOnCloseRequest(event -> {
            if (runtime != null) {
                runtime.close();
            }
        });

        stage.show();

    }

    private void showError(
            String title,
            Exception ex
    ) {
       ex.printStackTrace();

       Alert alert = new Alert(Alert.AlertType.ERROR);
       alert.setTitle("BeSafe");
       alert.setHeaderText(title);
       alert.setContentText(ex.getMessage());
       alert.showAndWait();
    }

    private void showWarning(
            String title,
            String message
    ) {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle("BeSafe");
        alert.setHeaderText(title);
        alert.setContentText(message);
        alert.show();
    }

    public static void main(String[] args) throws InterruptedException {
        launch(args);
    }

}