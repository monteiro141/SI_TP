package com.sitp.challengeaccepted.client;

import javafx.application.Application;
import javafx.beans.binding.Bindings;
import javafx.beans.binding.NumberBinding;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;

import java.io.IOException;

public class Client extends Application {
    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxloader = new FXMLLoader(Client.class.getResource("login_register_menu.fxml"));
        Scene scene = new Scene(fxloader.load(), 600, 400);
        stage.setMinWidth(700);
        stage.setMinHeight(400);
        stage.setTitle("Challenge Accepted");
        stage.setScene(scene);
        stage.show();

        controller control = fxloader.getController();
        control.gridCenter.setPrefWidth(150);
        control.Login.setPrefWidth(150);
        control.Registar.setPrefWidth(150);
        //control.resize();

        control.titleElement.wrappingWidthProperty().bind(scene.widthProperty().subtract(15));
        //control.titleElement.minHeight((scene.getHeight()) - (scene.getHeight()))
    }

    public static void main(String[] args) {
        launch();
    }
}