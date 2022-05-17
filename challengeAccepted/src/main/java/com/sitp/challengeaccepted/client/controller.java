package com.sitp.challengeaccepted.client;

import com.sitp.challengeaccepted.atributes.CipherChallengesAttributes;
import com.sitp.challengeaccepted.atributes.HashChallengesAttributes;
import javafx.event.ActionEvent;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.text.Text;
import javafx.stage.Stage;

import javax.crypto.*;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

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
    public Text textCredentials;

    //control variables for credentials_client_menu.fxml
    public static boolean login_access = false;

    //function to submit login or register data to server , as well if user did login or register
    public void submit_data_server(ActionEvent event) throws IOException{
        //warning server if user choosed login or register
        if(login_access){
            try {
                send_Login_Register("login");
            } catch (NoSuchPaddingException | BadPaddingException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }else{
            try {
                send_Login_Register("register");
            } catch (NoSuchPaddingException | BadPaddingException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        if(event.getSource() instanceof Button){
            Button buttonPressed = (Button) event.getSource();
            String nameOfButton = buttonPressed.getText();
        }

        //function to validate register/login done by user
        verifyLoginRegister(event);
    }

    public void dataExchange() throws NoSuchPaddingException, IOException, BadPaddingException, NoSuchAlgorithmException, ClassNotFoundException {
        initiateSocket();
        generateKeys();
        //send 4 keys to server
        cipherKeys(Client.is,Client.os);
    }
    //END GROUP 2 -------------------------------

    //Group 3 - Elements of Main Menu => main_menu.fxml
    public Button createChallengeButton;
    public Button resolveChallengeButton;
    public Button logoutButton;

    //END GROUP 3 -------------------------------

    //Group 4 - Elements of create challenge menu
    public Text createChallengeText;
    public MenuButton dropdownTypeChallenge;
    public MenuItem cipherChoice;
    public MenuItem hashChoice;

    public ChoiceBox<String>  dropdownTypes;

    public TextField messageInsert;
    public TextField tips;
    public TextField passInsert;

    public Button insertButton;
    public Button cancelButton;

    //list of cipher modes
    public static String[] cipherModes = {"AES-128-ECB","AES-128-CBC","AES-128-CTR","VIGENERE","CESAR"};
    //list of hash modes
    public static String[] hashModes = {"MD5","SHA256","SHA512"};

    public void cipherChoiceInput(ActionEvent event){
        dropdownTypeChallenge.setText("Cifra");
        dropdownTypes.setDisable(false);
        messageInsert.setDisable(false);
        tips.setDisable(false);
        passInsert.setDisable(false);

        messageInsert.clear();
        tips.clear();
        passInsert.clear();
        dropdownTypes.getItems().clear();
        dropdownTypes.getItems().addAll(cipherModes);
        dropdownTypes.setValue(cipherModes[0]);
        verifyContentTypes();
    }

    public void hashChoiceInput(ActionEvent event){
        dropdownTypeChallenge.setText("Hash");
        dropdownTypes.setDisable(false);
        messageInsert.setDisable(false);
        tips.setDisable(false);
        passInsert.setDisable(true);
        messageInsert.clear();
        tips.clear();
        passInsert.clear();
        dropdownTypes.getItems().clear();
        dropdownTypes.getItems().addAll(hashModes);
        dropdownTypes.setValue(hashModes[0]);
        verifyContentTypes();
    }

    public boolean verifyMessageVigCes(String message){
        if (message.matches("[a-zA-Z]+$")) {
            return true;
        }
        return false;
    }

    public void verifyContentTypes(){

        dropdownTypes.showingProperty().addListener((observable, oldValue, newValue) ->{
            messageInsert.clear();
            tips.clear();
            passInsert.clear();
            insertButton.setDisable(true);
        });

        //TODO: VERIFICATION OF LENGTH OF ELEMENTS
        //messageInsert.getText().length() <= 128) && (tips.getText().length() <= 128)

        messageInsert.textProperty().addListener((observable, oldValue, newValue) ->{
            //for cipher challenges
            if(!passInsert.isDisable() && !newValue.equals("") && !tips.getText().equals("") && !passInsert.getText().equals("")){
                switch (dropdownTypes.getValue()){
                    case "VIGENERE":
                        insertButton.setDisable(!verifyMessageVigCes(messageInsert.getText()) || !verifyMessageVigCes(passInsert.getText()));
                        break;
                    case "CESAR":
                        insertButton.setDisable(!verifyMessageVigCes(messageInsert.getText()) || !(passInsert.getText().matches("\\d+") && Integer.parseInt(passInsert.getText()) >= 1 && Integer.parseInt(passInsert.getText()) <= 25));
                        break;
                    default:
                        insertButton.setDisable(false);
                }
            }//for hash challenges
            else if (passInsert.isDisable() && !newValue.equals("") && !tips.getText().equals("")){
                //enable button
                insertButton.setDisable(false);
            }else {
                //disable
                insertButton.setDisable(true);
            }
        });

       tips.textProperty().addListener((observable, oldValue, newValue) ->{
           //for cipher challenges
           if(!passInsert.isDisable() && !newValue.equals("") && !messageInsert.getText().equals("") && !passInsert.getText().equals("")){
               switch (dropdownTypes.getValue()){
                   case "VIGENERE":
                       insertButton.setDisable(!verifyMessageVigCes(messageInsert.getText()) || !verifyMessageVigCes(passInsert.getText()));
                       break;
                   case "CESAR":
                       insertButton.setDisable(!verifyMessageVigCes(messageInsert.getText()) || !(passInsert.getText().matches("\\d+") && Integer.parseInt(passInsert.getText()) >= 1 && Integer.parseInt(passInsert.getText()) <= 25));
                       break;
                   default:
                       insertButton.setDisable(false);
               }
           }//for hash challenges
           else if (passInsert.isDisable() && !newValue.equals("") && !messageInsert.getText().equals("")){
               //enable button
               insertButton.setDisable(false);
           }else {
               //disable
               insertButton.setDisable(true);
           }
        });

       if(!passInsert.isDisable()) {
           passInsert.textProperty().addListener((observable, oldValue, newValue) -> {
               if(!newValue.equals("") && !tips.getText().equals("") && !messageInsert.getText().equals("")){
                   switch (dropdownTypes.getValue()){
                       case "VIGENERE":
                           insertButton.setDisable(!verifyMessageVigCes(messageInsert.getText()) || !verifyMessageVigCes(passInsert.getText()));
                           break;
                       case "CESAR":
                           insertButton.setDisable(!verifyMessageVigCes(messageInsert.getText()) || !(passInsert.getText().matches("\\d+") && Integer.parseInt(passInsert.getText()) >= 1 && Integer.parseInt(passInsert.getText()) <= 25));
                           break;
                       default:
                           insertButton.setDisable(false);
                   }
               }
              else {
                   //disable
                   insertButton.setDisable(true);
               }
           });
       }
    }

    //after values are inserted in create challenge send types of data according to type of challenge selected
    public void insertButtonInput(ActionEvent event){
        try {
            byte[] sendTypeChallenge = CipherDecipherClient.encrypt(dropdownTypeChallenge.getText(),Client.client_server,"AES",null);
            byte[] sendTypeChallengeHash = CipherDecipherClient.encrypt(getHash(dropdownTypeChallenge.getText()),Client.client_server_hash,"AES",null);

            byte[] sendType = CipherDecipherClient.encrypt(dropdownTypes.getValue(), Client.client_server,"AES",null);
            byte[] sendTypeHash = CipherDecipherClient.encrypt(getHash(dropdownTypes.getValue()), Client.client_server_hash,"AES",null);

            byte[] sendMessage = CipherDecipherClient.encrypt(messageInsert.getText(),Client.client_server,"AES",null);
            byte[] sendMessageHash = CipherDecipherClient.encrypt(getHash(messageInsert.getText()),Client.client_server_hash,"AES",null);

            byte[] sendTips = CipherDecipherClient.encrypt(tips.getText(),Client.client_server,"AES",null);
            byte[] sendTipsHash = CipherDecipherClient.encrypt(getHash(tips.getText()),Client.client_server_hash,"AES",null);

            Client.os.writeObject(sendTypeChallenge);
            Client.os.writeObject(sendTypeChallengeHash);
            Client.os.flush();

            Client.os.writeObject(sendType);
            Client.os.writeObject(sendTypeHash);
            Client.os.flush();

            Client.os.writeObject(sendMessage);
            Client.os.writeObject(sendMessageHash);
            Client.os.flush();

            Client.os.writeObject(sendTips);
            Client.os.writeObject(sendTipsHash);
            Client.os.flush();

            if(!passInsert.isDisable()) {
                byte[] sendPassword = CipherDecipherClient.encrypt(passInsert.getText(), Client.client_server, "AES", null);
                byte[] sendPasswordHash = CipherDecipherClient.encrypt(getHash(passInsert.getText()), Client.client_server_hash, "AES", null);
                Client.os.writeObject(sendPassword);
                Client.os.writeObject(sendPasswordHash);
                Client.os.flush();
            }

        } catch (BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }

        boolean validity = verifyResponsesValid();
        if(validity){
            createChallengeText.setText("Desafio criado com sucesso!");
            try {
                TimeUnit.SECONDS.sleep(2);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            try {
                switchMainMenu(event);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }else{
            createChallengeText.setText("Insucesso! Volte a criar!");
            sendOperationMethodstoServer("create");
        }
    }

    //END GROUP 4 -------------------------------

    //Group 5 - Elements of resolve challenge menu
    public Text title_resolve;

    public MenuButton dropdownTypeChoose;
    public MenuItem cipherChoice_resolve;
    public MenuItem hashChoice_resolve;

    public ChoiceBox dropdownChoose;
    public Text typeText;

    public Text challenge_content;
    public Text challenge_content_text;

    public Text challenge_tips;
    public Text challenge_tips_text;

    public TextField challenge_answer;
    public Text challenge_answer_text;

    public Button insertButtonChoose;
    public Button cancelButtonChoose;

    private static ArrayList<CipherChallengesAttributes> cipherResponse;
    private static ArrayList<HashChallengesAttributes> hashResponse;

    //function for button insert in resolve challenge menu
    public void insertButtonResolve(ActionEvent ent){
        //send type of challenge
        sendResolveDataToServer(dropdownTypeChoose.getText());
        //send id of challenge
        sendResolveDataToServer(dropdownChoose.getValue().toString());
        //send answer of challenge
        sendResolveDataToServer(challenge_answer.getText());
    }

    public void sendResolveDataToServer(String sent_data){
        try{
            byte[] sendData = CipherDecipherClient.encrypt(sent_data,Client.client_server,"AES",null);
            byte[] sendData_Hash = CipherDecipherClient.encrypt(getHash(sent_data),Client.client_server_hash,"AES",null);

            Client.os.writeObject(sendData);
            Client.os.writeObject(sendData_Hash);
            Client.os.flush();
        } catch (NoSuchPaddingException | BadPaddingException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    public void controlResolveElements(){
        dropdownTypeChoose.showingProperty().addListener((observable, oldValue, newValue) ->{
            //dropdownChoose.
            challenge_answer.clear();
            insertButtonChoose.setDisable(true);
        });

        dropdownChoose.showingProperty().addListener((observable, oldValue, newValue) ->{
            challenge_answer.clear();
            insertButtonChoose.setDisable(true);
        });

        challenge_content.textProperty().addListener((observable, oldValue, newValue) ->{
            if(!(challenge_content.getText().equals(""))){
                insertButtonChoose.setDisable(false);
            }
        });
    }

    //when user chooses type "Cifra"
    public void cipherChoose_resolve(){
        if(cipherResponse.size() != 0) {
            dropdownChoose.setDisable(false);
            challenge_answer.setDisable(false);
            challenge_content_text.setText("Criptograma :");
            dropdownChoose.setValue(cipherResponse.get(0));

            if(dropdownChoose.getValue().toString().toLowerCase().contains("cesar"))
                challenge_answer_text.setText("Offset :");
            else
                challenge_answer_text.setText("Palavra Passe :");

            dropdownChoose.getItems().clear();

            ChoiceBox<CipherChallengesAttributes> AUX = new ChoiceBox<CipherChallengesAttributes>();

            for(CipherChallengesAttributes element: cipherResponse){
                AUX.getItems().add(element);
            }

            dropdownChoose.getItems().addAll(AUX.getItems());
            challenge_answer.clear();
            title_resolve.setText("Resolver Desafio");
            controlResolveElements();
        }else{
            title_resolve.setText("Não existem desafios de cifra!");
        }
    }

    //when user chooses type "Hash"
    public void hashChoose_resolve(){
        if(hashResponse.size() != 0) {
            dropdownChoose.setDisable(false);
            challenge_answer.setDisable(false);
            challenge_content_text.setText("Hash :");
            challenge_answer_text.setText("Mensagem :");

            dropdownChoose.getItems().clear();

            ChoiceBox<HashChallengesAttributes> AUX = new ChoiceBox<HashChallengesAttributes>();

            for(HashChallengesAttributes element: hashResponse){
                AUX.getItems().add(element);
            }

            dropdownChoose.getItems().addAll(AUX.getItems());
            dropdownChoose.setValue(hashResponse.get(0));

            challenge_answer.clear();
            title_resolve.setText("Resolver Desafio");
            controlResolveElements();
        }else{
            title_resolve.setText("Não existem desafios de hash!");
        }
    }

    public void chooseTypeChallenge(ActionEvent event){

    }



    //END GROUP 5 -------------------------------

    //Group Scenes - Functions to change scenes => to change fxml files (pages)
    public void switchLoginMenu(ActionEvent event) throws IOException{

        login_access = false;

        //send operation "logout" to server
        sendOperationMethodstoServer("logout");

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

    public void switchMainMenu(ActionEvent event) throws IOException{
        //stage switching and creation
        root = FXMLLoader.load(Client.class.getResource("main_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root,stage.getWidth(),stage.getHeight());
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();
    }

    public void switchMainMenuCreateChallenge(ActionEvent event) throws IOException{

        //send operation "cancel" to server
        sendOperationMethodstoServer("cancel");

        verifyResponses();

        //stage switching and creation
        root = FXMLLoader.load(Client.class.getResource("main_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root,stage.getWidth(),stage.getHeight());
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();
    }

    public void switchMainMenuChooseChallenge(ActionEvent event) throws IOException{

        //send operation "cancel" to server
        sendOperationMethodstoServer("cancel");

        verifyResponses();

        //stage switching and creation
        root = FXMLLoader.load(Client.class.getResource("main_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root,stage.getWidth(),stage.getHeight());
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();
    }

    //before going to create_challenge_menu ,send type of operation chosen
    public void sendOperationMethodstoServer(String data){
        try {
            byte [] sendOperationCreate = CipherDecipherClient.encrypt(data,Client.client_server,"AES",null);
            byte [] sendOperationCreateHash = CipherDecipherClient.encrypt(getHash(data),Client.client_server_hash,"AES",null);

            Client.os.writeObject(sendOperationCreate);
            Client.os.writeObject(sendOperationCreateHash);
            Client.os.flush();
        } catch (BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    public void switchCreateChallengeMenu(ActionEvent event) throws IOException{

        //send type of operation "create" to inform server that user has chosen to create a challenge
        sendOperationMethodstoServer("create");

        //stage switching and creation
        root = FXMLLoader.load(Client.class.getResource("create_challenge.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root,stage.getWidth(),stage.getHeight());
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();
    }

    public void switchChooseChallengeMenu(ActionEvent event) throws IOException{

        //send type of operation "resolve" to inform server that user has chosen to resolve a challenge
        sendOperationMethodstoServer("resolve");

        //receive lists of cipher and hash from server
        boolean changeView = verifyResponsesLists();

        if(changeView) {
            //stage switching and creation
            root = FXMLLoader.load(Client.class.getResource("resolve_challenge.fxml"));
            stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
            scene = new Scene(root,stage.getWidth(),stage.getHeight());
            stage.setMinWidth(600);
            stage.setMinHeight(400);
            stage.setScene(scene);
            stage.show();
        }else{
            try {
                PopoutEmptyLists.display("Sem desafios!","Não existem desafios para resolver! Tente mais tarde!");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
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
        //Socket S = new Socket("169.254.65.233",1099);
        Socket S = new Socket("127.0.0.1",1099);
        //Socket S = new Socket("5.tcp.eu.ngrok.io",16672);
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

    private void send_Login_Register(String data) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException {
        byte [] login_bytes = CipherDecipherClient.encrypt(data,Client.client_server,"AES",null);
        byte [] login_bytes_hash = CipherDecipherClient.encrypt(getHash(data),Client.client_server_hash,"AES",null);

        byte [] email_bytes = CipherDecipherClient.encrypt(emailInput.getText(),Client.client_server,"AES",null);
        byte [] email_hash_bytes = CipherDecipherClient.encrypt(getHash(emailInput.getText()),Client.client_server_hash,"AES",null);

        byte [] password_bytes = CipherDecipherClient.encrypt(passwordInput.getText(),Client.client_server,"AES",null);
        byte [] password_hash_bytes = CipherDecipherClient.encrypt(getHash(passwordInput.getText()),Client.client_server_hash,"AES",null);

        try{
            Client.os.writeObject(login_bytes);
            Client.os.writeObject(login_bytes_hash);
            Client.os.flush();

            Client.os.writeObject(email_bytes);
            Client.os.writeObject(email_hash_bytes);
            Client.os.flush();

            Client.os.writeObject(password_bytes);
            Client.os.writeObject(password_hash_bytes);
            Client.os.flush();
        }catch(IOException e){
            System.out.println("Connection closed");
        }

    }

    //function to verify if the keys are the same by comparing hash
    public void verifyResponses(){
        try {
            byte[] typeResponse = (byte[]) Client.is.readObject();
            byte[] typeResponseHash = (byte[]) Client.is.readObject();

            String decipheredtypeResponse = CipherDecipherClient.decrypt(typeResponse,Client.server_client,"AES",null);
            String decipheredtypeResponseHash = CipherDecipherClient.decrypt(typeResponseHash,Client.server_client_hash,"AES",null);

            if(getHash(decipheredtypeResponse).equals(decipheredtypeResponseHash)){
                //System.out.println("They are the same");
            }else{
                System.out.println("Not the same");
            }
        } catch (IOException | ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException | NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    public void receiveSizeLists(String option, String responseSizeResponse, byte[] data, byte[] dataHash){
        switch (option){
            case "CIFRA":
                if(!(responseSizeResponse.equals("empty"))){
                    //receive first cipher challenges list
                    try {
                        data = (byte[]) Client.is.readObject();
                        dataHash = (byte[]) Client.is.readObject();
                    } catch (IOException | ClassNotFoundException e) {
                        e.printStackTrace();
                    }

                    try {
                        cipherResponse = CipherDecipherClient.CipherdecryptLists(data, Client.server_client, "AES", null);
                    } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                        e.printStackTrace();
                    }
                }else{
                    cipherResponse = new ArrayList<>();
                }
                break;

            case "HASH":
                if(!(responseSizeResponse.equals("empty"))){
                    //receive second hash challenges list
                    try {
                        data = (byte[]) Client.is.readObject();
                        dataHash = (byte[]) Client.is.readObject();
                    } catch (IOException | ClassNotFoundException e) {
                        e.printStackTrace();
                    }

                    try {
                        hashResponse = CipherDecipherClient.HashdecryptLists(data, Client.server_client, "AES", null);
                    } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                        e.printStackTrace();
                    }
                }else{
                    hashResponse = new ArrayList<>();
                }
                break;
        }
    }

    public boolean verifyResponsesLists(){
        String responseSizeResponse="";
        String responseSizeHashResponse="";

        String responseSizeResponseV2="";
        String responseSizeHashResponseV2="";
        try{
            //receive server response for size of lists => first response
            byte[] responseSize = (byte[]) Client.is.readObject();
            byte[] responseSizeHash = (byte[]) Client.is.readObject();

            //receive server response for size of lists => second response
            byte[] responseSizeV2 = (byte[]) Client.is.readObject();
            byte[] responseSizeHashV2 = (byte[]) Client.is.readObject();

            responseSizeResponse = CipherDecipherClient.decrypt(responseSize,Client.server_client,"AES",null);
            responseSizeHashResponse = CipherDecipherClient.decrypt(responseSizeHash,Client.server_client_hash,"AES",null);

            responseSizeResponseV2 = CipherDecipherClient.decrypt(responseSizeV2,Client.server_client,"AES",null);
            responseSizeHashResponseV2 = CipherDecipherClient.decrypt(responseSizeHashV2,Client.server_client_hash,"AES",null);

        } catch (NoSuchPaddingException | IllegalBlockSizeException | IOException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        byte[] responseCipher = new byte[0];
        byte[] responseCipherHash = new byte[0];
        byte[] responseHash = new byte[0];
        byte[] responseHashHash = new byte[0];

        if(!(responseSizeResponse.equals("empty")) || !(responseSizeResponseV2.equals("empty"))) {

            //cipher received first
            receiveSizeLists("CIFRA",responseSizeResponse,responseCipher,responseCipherHash);

            //hash received second
            receiveSizeLists("HASH",responseSizeResponseV2,responseHash,responseHashHash);

            for (CipherChallengesAttributes element : cipherResponse) {
                System.out.println(element.toString());
            }

            System.out.println("---------------------------");

            for (HashChallengesAttributes element : hashResponse) {
                System.out.println(element.toString());
            }
            return true;
        }
        return false;
    }

    //function to verify if operation is valid or invalid
    public boolean verifyResponsesValid(){
        try {
            byte[] typeResponse = (byte[]) Client.is.readObject();
            byte[] typeResponseHash = (byte[]) Client.is.readObject();

            String decipheredtypeResponse = CipherDecipherClient.decrypt(typeResponse,Client.server_client,"AES",null);
            String decipheredtypeResponseHash = CipherDecipherClient.decrypt(typeResponseHash,Client.server_client_hash,"AES",null);

            System.out.println(decipheredtypeResponse);
            System.out.println(decipheredtypeResponseHash);

            if(getHash(decipheredtypeResponse).equals(decipheredtypeResponseHash)){
                if(decipheredtypeResponse.equals("true")){
                    return true;
                }
            }else{
                System.out.println("Not the same");
            }
        } catch (IOException | ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException | NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException e) {
            e.printStackTrace();
        }
        return false;
    }

    public void verifyLoginRegister(ActionEvent event) {
        try {
            byte[] statusResponse = (byte[]) Client.is.readObject();
            byte[] statusResponseHash = (byte[]) Client.is.readObject();
            String decipheredResponseStatus = CipherDecipherClient.decrypt(statusResponse, Client.server_client, "AES", null);
            String decipheredResponseStatusHash = CipherDecipherClient.decrypt(statusResponseHash, Client.server_client_hash, "AES", null);

            System.out.println("LOGIN/REGISTER STATUS: " + decipheredResponseStatus);
            System.out.println("LOGIN/REGISTER STATUSHASH: " + decipheredResponseStatusHash);

            if (getHash(decipheredResponseStatus).equals(decipheredResponseStatusHash)) {
                //System.out.println("They are the same!");
                if(Boolean.parseBoolean(decipheredResponseStatus)){
                    System.out.println("Login bem sucedido!");
                    switchMainMenu(event);
                }else{
                    textCredentials.setText("Credenciais incorretas!");
                }
            } else {
                //System.out.println("They are not the same!");
            }
        } catch (IOException | ClassNotFoundException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }
    // END GROUP 3 - Group of operations
}