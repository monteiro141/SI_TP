package com.sitp.challengeaccepted.client;

import javafx.event.ActionEvent;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Pane;
import javafx.scene.text.Text;
import javafx.stage.Stage;

import java.io.IOException;

public class controller {

    //Group 1 - Main Page Elements
    //elements for main menu page => login_register_menu.fxml
    public Text titleElement;
    public BorderPane borderPaneLogin;
    public GridPane gridCenter;
    public Button Login;
    public Button Registar;
    public Pane optionsPane;
    private Stage stage;
    private Scene scene;
    private Parent root;
    //END GROUP 1 -------------------------------

    //Group 2 - Login & Register Page Elements
    //elements for login and register page => credentials_client_menu.fxml
    public TextField emailInput;
    public TextField passwordInput;


    //(implement controllers afterwards => and text and button elements)
    //END GROUP 2 -------------------------------


    //Group Scenes - Functions to change scenes => to change fxml files (pages)
    public void switchLoginMenu(ActionEvent event) throws IOException{
        root = FXMLLoader.load(Client.class.getResource("login_register_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root,600,400);
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();
    }

    public void switchCredentialsMenuLogin(ActionEvent event) throws IOException{

        //stage switching and creation
        root = FXMLLoader.load(Client.class.getResource("credentials_client_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root,stage.getWidth(),stage.getHeight());
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();

        //warning server if user choosed login or register
    }

    public void switchCredentialsMenuRegister(ActionEvent event) throws IOException{

        //stage switching and creation
        root = FXMLLoader.load(Client.class.getResource("credentials_client_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root,stage.getWidth(),stage.getHeight());
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();

        //warning server if user choosed login or register
    }
    //...

    //END GROUP SCENES -------------------------------
}