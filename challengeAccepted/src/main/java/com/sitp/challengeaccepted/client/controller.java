package com.sitp.challengeaccepted.client;

import javafx.event.ActionEvent;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Pane;
import javafx.scene.text.Text;
import javafx.stage.Stage;

import java.io.IOException;

public class controller {
    public boolean buttonLoginState = false;

    public Text titleElement;

    public BorderPane borderPaneLogin;

    public GridPane gridCenter;

    public Button Login;

    public Button Registar;

    public Pane optionsPane;

    private Stage stage;
    private Scene scene;
    private FXMLLoader fxmlLoader;
    private Parent root;

    public void switchLoginMenu(ActionEvent event) throws IOException{
        root = FXMLLoader.load(Client.class.getResource("login_register_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    public void switchCredentialsMenu(ActionEvent event) throws IOException{
        root = FXMLLoader.load(Client.class.getResource("credentials_client_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    public void resize(){
        optionsPane.setMaxSize(2000,1000);
    }
}