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

import javax.crypto.*;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

public class controller {

    //Group 1 - Main Page Elements
    //elements for main menu page => login_register_menu.fxml
    public Text titleElement;
    public BorderPane borderPaneLogin;
    public GridPane gridCenter;
    public Button Login;
    public Button Registar;
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

    //Group 3 - Group of operations


    //control variables for fxml
    public static boolean login_access = false;
    public static boolean login_method = false;
    public static boolean register_access = false;
    //END GROUP 3 -------------------------------

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

    public void switchCredentialsMenuLogin(ActionEvent event) throws IOException, NoSuchAlgorithmException {
        //stage switching and creation
        FXMLLoader fxmlLoader = new FXMLLoader(Client.class.getResource("credentials_client_menu.fxml"));
        //fxmlLoader.setController(Client.control);
        root = fxmlLoader.load();
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root,stage.getWidth(),stage.getHeight());
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();

        //warning server if user choosed login or register
        login_access = true;
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
    }

    public void submit_data_server(ActionEvent event) throws IOException{
        //TODO => main page of user after sucessfull login/register

        //warning server if user choosed login or register
        if(login_access){
            login_method = true;
            try {
                send_Login_Register();
            } catch (NoSuchPaddingException | BadPaddingException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }else{
            register_access = true;
            try {
                send_Login_Register();
            } catch (NoSuchPaddingException | BadPaddingException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        if(event.getSource() instanceof Button){
            Button buttonPressed = (Button) event.getSource();
            String nameOfButton = buttonPressed.getText();
            System.out.println(nameOfButton);
        }

    }

    public void dataExchange() throws NoSuchPaddingException, IOException, BadPaddingException, NoSuchAlgorithmException, ClassNotFoundException {
        initiateSocket();
        generateKeys();
        //send 4 keys to server
        cipherKeys(Client.is,Client.os);
    }
    //...

    //END GROUP SCENES -------------------------------

    //Group 3 - Group of operations

    // generate 4 keys for client
    private void generateKeys() throws NoSuchAlgorithmException {
        Client.client_server = generateKey("AES",128);
        Client.client_server_hash = generateKey("AES",128);
        Client.server_client = generateKey("AES",128);
        Client.server_client_hash = generateKey("AES",128);
    }

    //function to generate first 4 keys of the client
    private static SecretKey generateKey(String cipher_mode, int sizeKey) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerated = KeyGenerator.getInstance(cipher_mode);
        keyGenerated.init(sizeKey);
        return keyGenerated.generateKey();
    }

    //function to initiate socket connection to server
    private void initiateSocket() throws IOException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, ClassNotFoundException {
        Socket S = new Socket("169.254.228.94",1099);
        Client.os = new ObjectOutputStream(S.getOutputStream());
        Client.is = new ObjectInputStream(S.getInputStream());
    }

    private void cipherKeys(ObjectInputStream public_key_server, ObjectOutputStream send_server) throws IOException, ClassNotFoundException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException {
        PublicKey key_server = (PublicKey) public_key_server.readObject();

        //cipher keys to send to server
        byte[] client_Server_cipher = CipherDecipherClient.encrypt(Base64.getEncoder().encodeToString(Client.client_server.getEncoded()),key_server);
        byte[] client_Server_cipher_hashes = CipherDecipherClient.encrypt(Base64.getEncoder().encodeToString(Client.client_server_hash.getEncoded()),key_server);
        byte[] server_Client_cipher = CipherDecipherClient.encrypt(Base64.getEncoder().encodeToString(Client.server_client.getEncoded()),key_server);
        byte[] server_Client_cipher_hashes = CipherDecipherClient.encrypt(Base64.getEncoder().encodeToString(Client.server_client_hash.getEncoded()),key_server);

        //send keys to server
        send_server.write(client_Server_cipher);
        send_server.write(client_Server_cipher_hashes);
        send_server.write(server_Client_cipher);
        send_server.write(server_Client_cipher_hashes);
        send_server.flush();
    }

    private String getHash(String content){
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(content.getBytes());
            return new String(md.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    private void send_Login_Register() throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException {
        if(login_method){
            byte [] login_bytes = CipherDecipherClient.encrypt("login",Client.client_server,"AES",null);
            byte [] login_bytes_hash = CipherDecipherClient.encrypt(getHash("login"),Client.client_server_hash,"AES",null);
            try{
                Client.os.writeObject(login_bytes);
                Client.os.writeObject(login_bytes_hash);
                Client.os.flush();
            }catch(IOException e){
                System.out.println("Connection closed");
            }
            login_method = false;

            //uncomment when server sends responses
            //verifyResponses();
        }

        if(register_access){
            byte [] register_bytes = CipherDecipherClient.encrypt("register",Client.client_server,"AES",null);
            byte [] register_bytes_hash = CipherDecipherClient.encrypt(getHash("register"),Client.client_server_hash,"AES",null);
            try{
                Client.os.writeObject(register_bytes);
                Client.os.writeObject(register_bytes_hash);
                Client.os.flush();
            }catch(SocketException e){
                System.out.println("Connection closed");
            } catch (IOException e) {
                e.printStackTrace();
            }
            register_access = false;

            //uncomment when server sends responses
            //verifyResponses();
        }
    }

    //function to verify if the keys are the same by comparing hash
    public void verifyResponses(){
        try {
            byte[] typeResponse = (byte[]) Client.is.readObject();
            byte[] typeResponseHash = (byte[]) Client.is.readObject();

            String decipheredtypeResponse = CipherDecipherClient.decrypt(typeResponse,Client.server_client,"AES",null);
            String decipheredtypeResponseHash = CipherDecipherClient.decrypt(typeResponseHash,Client.server_client_hash,"AES",null);

            System.out.println(decipheredtypeResponse);
            System.out.println(decipheredtypeResponseHash);

            if(getHash(decipheredtypeResponse).equals(decipheredtypeResponseHash)){
                System.out.println("They are the same");
            }else{
                System.out.println("Not the same");
            }
        } catch (IOException | ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException | NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException e) {
            e.printStackTrace();
        }
    }
    // END GROUP 3 - Group of operations


}