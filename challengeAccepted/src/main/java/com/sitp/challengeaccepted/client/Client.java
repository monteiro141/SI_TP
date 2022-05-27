package com.sitp.challengeaccepted.client;

import com.sitp.challengeaccepted.server.CipherDecipher;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.binding.Bindings;
import javafx.beans.binding.NumberBinding;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;

import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;



public class Client extends Application {
    public static SecretKey client_server;
    public static SecretKey client_server_hash;
    public static SecretKey server_client;
    public static SecretKey server_client_hash;
    public static ObjectInputStream is;
    public static ObjectOutputStream os;

    String imagePath = "file:src/main/resources/com/sitp/challengeaccepted/client/cyber-security.png";

    public Client(){

    }

    /**
     * Function to launch initial menu for user
     * @param stage stage of the application
     * @throws IOException
     */
    @Override
    public void start(Stage stage) throws IOException{
        initiateMenu(stage);
    }

    /**
     * Function to launch the application
     * @param args
     */
    public static void main(String[] args){
        launch();
    }

    /**
     * Function to initiate first menu for user
     * @param stage stage of the application
     * @throws IOException
     */
    //function to initiate main menu of application
    private void initiateMenu(Stage stage) throws IOException {
        FXMLLoader fxloader = new FXMLLoader(Client.class.getResource("login_register_menu.fxml"));
        Scene scene = new Scene(fxloader.load(), 600, 400);
        stage.getIcons().add(new Image(imagePath));
        stage.setResizable(false);
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setTitle("Challenge Accepted");
        stage.setScene(scene);
        stage.show();
        try {
            ((controller) fxloader.getController()).dataExchange();
        } catch (NoSuchPaddingException | BadPaddingException | NoSuchAlgorithmException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}

