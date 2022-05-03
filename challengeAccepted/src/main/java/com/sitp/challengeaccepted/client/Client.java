package com.sitp.challengeaccepted.client;

import com.sitp.challengeaccepted.server.CipherDecipher;
import javafx.application.Application;
import javafx.beans.binding.Bindings;
import javafx.beans.binding.NumberBinding;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
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
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

public class Client extends Application {

    private SecretKey client_server;
    private SecretKey client_server_hash;
    private SecretKey server_client;
    private SecretKey server_client_hash;

    public Client(){

    }

    @Override
    public void start(Stage stage) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, ClassNotFoundException {
        initiateMenu(stage);
    }

    public static void main(String[] args) throws NoSuchPaddingException, IOException, BadPaddingException, NoSuchAlgorithmException, ClassNotFoundException {
        //operations to be executed before launch() instruction => before stage creation
        Client c = new Client();
        c.generateKeys();
        c.initiateSocket();

        //stage launching in window
        launch();

        while(true){

        }
        

        //interrupt connection when user exits window (TO ADD LATER)
    }

    //function to generate first 4 keys of the client
    private static SecretKey generateKey(String cipher_mode, int sizeKey) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerated = KeyGenerator.getInstance(cipher_mode);
        keyGenerated.init(sizeKey);
        return keyGenerated.generateKey();
    }

    //function to initiate main menu of application
    private void initiateMenu(Stage stage) throws IOException {
        FXMLLoader fxloader = new FXMLLoader(Client.class.getResource("login_register_menu.fxml"));
        Scene scene = new Scene(fxloader.load(), 600, 400);
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setTitle("Challenge Accepted");
        stage.setScene(scene);
        stage.show();
    }

    //function to initiate socket connection to server
    private void initiateSocket() throws IOException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, ClassNotFoundException {
        Socket S = new Socket("169.254.228.94",1099);
        ObjectOutputStream os = new ObjectOutputStream(S.getOutputStream());
        ObjectInputStream is = new ObjectInputStream(S.getInputStream());

        //send 4 keys to server
        cipherKeys(is,os);
    }

    private void generateKeys() throws NoSuchAlgorithmException {
        client_server = generateKey("AES",128);
        client_server_hash = generateKey("AES",128);
        server_client = generateKey("AES",128);
        server_client_hash = generateKey("AES",128);
    }

    private void cipherKeys(ObjectInputStream public_key_server, ObjectOutputStream send_server) throws IOException, ClassNotFoundException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException {
        PublicKey key_server = (PublicKey) public_key_server.readObject();

        //cipher keys to send to server
        byte[] client_Server_cipher = CipherDecipherClient.encrypt(Base64.getEncoder().encodeToString(client_server.getEncoded()),key_server);
        byte[] server_Client_cipher = CipherDecipherClient.encrypt(Base64.getEncoder().encodeToString(server_client.getEncoded()),key_server);
        byte[] client_Server_cipher_hashes = CipherDecipherClient.encrypt(Base64.getEncoder().encodeToString(server_client_hash.getEncoded()),key_server);
        byte[] server_Client_cipher_hashes = CipherDecipherClient.encrypt(Base64.getEncoder().encodeToString(client_server_hash.getEncoded()),key_server);

        //send keys to server
        send_server.write(client_Server_cipher);
        send_server.write(server_Client_cipher);
        send_server.write(client_Server_cipher_hashes);
        send_server.write(server_Client_cipher_hashes);
        send_server.flush();
    }
}

