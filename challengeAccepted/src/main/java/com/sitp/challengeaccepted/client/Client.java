package com.sitp.challengeaccepted.client;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class Client extends Application {
    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxloader = new FXMLLoader(Client.class.getResource("login_register_menu.fxml"));
        Scene scene = new Scene(fxloader.load(), 320, 240);
        stage.setTitle("Challenge Accepted");
        stage.setScene(scene);
        stage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}