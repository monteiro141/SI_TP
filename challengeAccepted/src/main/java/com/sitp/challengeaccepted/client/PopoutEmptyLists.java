package com.sitp.challengeaccepted.client;

import javafx.application.Application;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class PopoutEmptyLists{
    public static void display(String title, String message) throws Exception {
        Stage window = new Stage();

        //Block events from another windows
        window.initModality(Modality.APPLICATION_MODAL);
        window.setTitle(title);
        window.setWidth(400);
        window.setHeight(100);

        //Create a description
        Label label = new Label();
        label.setText(message);

        //Create a button exit for user
        Button okButton = new Button("OK");
        okButton.setOnAction(actionEvent -> window.close());

        //Create content box to display in window
        VBox layout = new VBox(10);
        layout.getChildren().addAll(label,okButton);
        layout.setAlignment(Pos.CENTER);

        //Display window and it's elements
        Scene scene = new Scene(layout);
        window.setScene(scene);
        window.showAndWait();

    }
}
