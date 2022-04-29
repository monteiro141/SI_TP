package com.sitp.challengeaccepted.client;

import javafx.scene.control.Button;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Pane;
import javafx.scene.text.Text;

public class controller {
    public Text titleElement;

    public BorderPane borderPaneLogin;

    public GridPane gridCenter;

    public Button Login;

    public Button Registar;

    public Pane optionsPane;

    public void resize(){
        optionsPane.setMaxSize(2000,1000);
    }


}