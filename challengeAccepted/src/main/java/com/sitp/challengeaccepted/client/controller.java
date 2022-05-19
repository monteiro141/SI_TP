package com.sitp.challengeaccepted.client;

import com.sitp.challengeaccepted.atributes.CipherChallengesAttributes;
import com.sitp.challengeaccepted.atributes.HashChallengesAttributes;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
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
    public PasswordField passwordInput;
    public Text textCredentials;
    public Button submit;
    public Button cancelButtonCredentials;

    //control variables for credentials_client_menu.fxml
    public static boolean login_access = false;
    public static boolean email_Valid = false;

    //function to submit login or register data to server , as well if user did login or register
    public void submit_data_server(ActionEvent event) throws IOException{
        //warning server if user choosed login or register
        if(login_access && email_Valid){
            try {
                send_Login_Register("login");
                //function to validate register/login done by user
                verifyLoginRegister(event);
            } catch (NoSuchPaddingException | BadPaddingException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }else if(email_Valid && !(passwordInput.getText().equals(""))){
            try {
                send_Login_Register("register");
                //function to validate register/login done by user
                verifyLoginRegister(event);
            } catch (NoSuchPaddingException | BadPaddingException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }else{
            textCredentials.setText("Credenciais incorretas!");
        }
        if(event.getSource() instanceof Button){
            Button buttonPressed = (Button) event.getSource();
            String nameOfButton = buttonPressed.getText();
        }

    }

    public void listenerElementsCredentialsMenu(){
        emailInput.textProperty().addListener((observable, oldValue, newValue) ->{
            if(verifyCredentialEmail(emailInput.getText())){
                email_Valid=true;
            }
            else{
                email_Valid=false;
            }
        });
    }

    public boolean verifyCredentialEmail(String message){
        if (message.matches("^(.+)@(.+)$")) {
            return true;
        }
        return false;
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
    public Text passInsertText;
    public TextField passInsert;

    public Button insertButton;
    public Button cancelButton;

    //list of cipher modes
    public static String[] cipherModes = {"AES-128-ECB","AES-128-CBC","AES-128-CTR","VIGENERE","CESAR","ELGAMAL"};
    //list of hash modes
    public static String[] hashModes = {"MD5","SHA256","SHA512"};

    public void cipherChoiceInput(ActionEvent event){
        dropdownTypeChallenge.setText("Cifra");
        typeText.setText("Tipo de Cifra:");
        dropdownTypes.setDisable(false);
        messageInsert.setDisable(false);
        tips.setDisable(false);
        passInsert.setDisable(false);

        messageInsert.clear();
        tips.clear();
        passInsertText.setText("Palavra Passe:");
        dropdownTypes.getItems().clear();
        dropdownTypes.getItems().addAll(cipherModes);
        dropdownTypes.setValue(cipherModes[0]);
        verifyContentTypes();
    }

    public void hashChoiceInput(ActionEvent event){
        dropdownTypeChallenge.setText("Hash");
        typeText.setText("Tipo de Hash:");
        dropdownTypes.setDisable(false);
        messageInsert.setDisable(false);
        tips.setDisable(false);
        passInsert.setDisable(true);

        messageInsert.clear();
        tips.clear();
        passInsertText.setText("Palavra Passe:");
        dropdownTypes.getItems().clear();
        dropdownTypes.getItems().addAll(hashModes);
        dropdownTypes.setValue(hashModes[0]);
        verifyContentTypes();
    }

    public boolean verifyMessageVigCes(String message){
        if (message.matches("[a-zA-Z\s]+$")) {
            return true;
        }
        return false;
    }

    public boolean verifyAESMessageRegex(String message){
        if(message.matches("^[ -~]*$")){
            return true;
        }
        return false;
    }

    public boolean verifyOffSetCesar(String message){
        if(message.matches("^([1-9]|1[0-9]|2[0-5])$")){
            return true;
        }
        return false;
    }

    public boolean verify128CharsElements(String message, String tips){
        if(message.length() <= 128 && tips.length() <= 128) {
            return true;
        }
        return false;
    }

    public boolean verifyElGamal(String message){
        if(message.matches("([2-9]|[1-9][0-9]{1,4}|[1-8][0-9]{5}|9[0-8][0-9]{4}|99[01][0-9]{3}|992[0-4][0-9]{2}|9925[0-8][0-9])")){
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

            if(dropdownTypes.getValue().equals("CESAR")){
                tips.setDisable(false);
                passInsertText.setText("Offset:");
            }else if(dropdownTypes.getValue().equals("ELGAMAL")){
                tips.setDisable(true);
                passInsertText.setText("y (1 < y < 120011728):");
            }else{
                tips.setDisable(false);
                passInsertText.setText("Palavra Passe:");
            }
        });

        messageInsert.textProperty().addListener((observable, oldValue, newValue) ->{
            //for cipher challenges
            if(!passInsert.isDisable() && !newValue.equals("") && (!tips.getText().equals("") || tips.isDisable()) && !passInsert.getText().equals("") && verify128CharsElements(messageInsert.getText(),tips.getText())){
                switch (dropdownTypes.getValue()){
                    case "VIGENERE":
                        insertButton.setDisable(!verifyMessageVigCes(messageInsert.getText()) || !verifyMessageVigCes(passInsert.getText()));
                        break;
                    case "CESAR":
                        insertButton.setDisable(!verifyMessageVigCes(messageInsert.getText()) || !(passInsert.getText().matches("\\d+") && Integer.parseInt(passInsert.getText()) >= 1 && Integer.parseInt(passInsert.getText()) <= 25));
                        break;
                    default:
                        insertButton.setDisable(!verifyAESMessageRegex(messageInsert.getText()));
                }
            }//for hash challenges
            else if (passInsert.isDisable() && !newValue.equals("") && !tips.getText().equals("") && verify128CharsElements(messageInsert.getText(),tips.getText())){
                //enable button
                insertButton.setDisable(false);
            }else {
                //disable
                insertButton.setDisable(true);
            }
        });

       tips.textProperty().addListener((observable, oldValue, newValue) ->{
           //for cipher challenges
           if(!passInsert.isDisable() && !newValue.equals("") && !messageInsert.getText().equals("") && !passInsert.getText().equals("") && verify128CharsElements(messageInsert.getText(),tips.getText())){
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
           else if (passInsert.isDisable() && !newValue.equals("") && !messageInsert.getText().equals("") && verify128CharsElements(messageInsert.getText(),tips.getText())){
               //enable button
               insertButton.setDisable(false);
           }else {
               //disable
               insertButton.setDisable(true);
           }
        });

       if(!passInsert.isDisable()) {
           passInsert.textProperty().addListener((observable, oldValue, newValue) -> {
               if(!newValue.equals("") && (!tips.getText().equals("") || tips.isDisable()) && !messageInsert.getText().equals("") && verify128CharsElements(messageInsert.getText(),tips.getText())){
                   switch (dropdownTypes.getValue()){
                       case "VIGENERE":
                           insertButton.setDisable(!verifyMessageVigCes(messageInsert.getText()) || !verifyMessageVigCes(passInsert.getText()));
                           break;
                       case "CESAR":
                           insertButton.setDisable(!verifyMessageVigCes(messageInsert.getText()) || !(verifyOffSetCesar(passInsert.getText())));
                           break;
                       case "ELGAMAL":
                           insertButton.setDisable(!verifyAESMessageRegex(messageInsert.getText()) || (!verifyElGamal(passInsert.getText())));
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


            Client.os.writeObject(sendTypeChallenge);
            Client.os.writeObject(sendTypeChallengeHash);
            Client.os.flush();

            Client.os.writeObject(sendType);
            Client.os.writeObject(sendTypeHash);
            Client.os.flush();

            Client.os.writeObject(sendMessage);
            Client.os.writeObject(sendMessageHash);
            Client.os.flush();

            //mode chosen is not ElGamal
            if(!tips.isDisable()){
                byte[] sendTips = CipherDecipherClient.encrypt(tips.getText(),Client.client_server,"AES",null);
                byte[] sendTipsHash = CipherDecipherClient.encrypt(getHash(tips.getText()),Client.client_server_hash,"AES",null);
                Client.os.writeObject(sendTips);
                Client.os.writeObject(sendTipsHash);
                Client.os.flush();
            }

            //type chosen is not hash
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

    public ChoiceBox dropdownTypeChoose;

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

    public ChangeListener<Number> changeListener;

    private static ArrayList<CipherChallengesAttributes> cipherResponse;
    private static ArrayList<HashChallengesAttributes> hashResponse;

    //function for button insert in resolve challenge menu
    public void insertButtonResolve(ActionEvent event){
        //send type of challenge
        String id = "";
        switch (dropdownTypeChoose.getValue().toString()){
            case "Cifra":
                id = String.valueOf(((CipherChallengesAttributes)dropdownChoose.getValue()).getChallenge_id());
                break;
            case "Hash":
                id = String.valueOf(((HashChallengesAttributes)dropdownChoose.getValue()).getHash_id());
                break;
        }

        //send data to server
        sendResolveDataToServer(dropdownTypeChoose.getValue().toString());
        sendResolveDataToServer(id);
        sendResolveDataToServer(challenge_answer.getText());

        verifyResponsesResolve(event);
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
        dropdownTypeChoose.getSelectionModel().selectedIndexProperty().addListener((observable, oldValue, newValue) ->{
                switch ((int) newValue){
                    case 0:
                        cipherChoose_resolve();
                        break;
                    case 1:
                        hashChoose_resolve();
                        break;
                }
                //challenge_answer.clear();
                insertButtonChoose.setDisable(true);
        });

        challenge_answer.textProperty().addListener((observable, oldValue, newValue) ->{
            if(!(challenge_answer.getText().equals(""))){
                insertButtonChoose.setDisable(false);
            }else{
                insertButtonChoose.setDisable(true);
            }
        });


        changeListener = new ChangeListener<Number>() {
            @Override
            public void changed(ObservableValue<? extends Number> observableValue, Number oldValue, Number newValue) {
                switch (dropdownTypeChoose.getValue().toString()) {
                    case "Cifra":
                        if (cipherResponse.size() == 0 || (int) newValue < 0)
                            break;
                        challenge_content.setText(cipherResponse.get((int) newValue).getCipher_message());
                        challenge_tips.setText(cipherResponse.get((int) newValue).getCipher_tips());
                        challenge_content_text.setText("Criptograma :");
                        if(dropdownChoose.getValue().toString().toLowerCase().contains("cesar"))
                            challenge_answer_text.setText("Offset :");
                        else
                            challenge_answer_text.setText("Palavra Passe :");
                        challenge_answer.setDisable(false);
                        break;
                    case "Hash":
                        if (hashResponse.size() == 0 || (int) newValue < 0)
                            break;
                        challenge_content.setText(hashResponse.get((int) newValue).getHash_hash());
                        challenge_tips.setText(hashResponse.get((int) newValue).getHash_tips());
                        challenge_content_text.setText("Hash :");
                        challenge_answer_text.setText("Mensagem :");
                        challenge_answer.setDisable(false);
                        break;
                }
            }
        };
    }

    //when user chooses type "Cifra"
    public void cipherChoose_resolve(){
        if(cipherResponse.size() != 0) {
            dropdownChoose.setDisable(false);
            challenge_answer.setDisable(false);

            dropdownChoose.getSelectionModel().selectedIndexProperty().removeListener(changeListener);
            challenge_content.setText("");
            challenge_tips.setText("");
            challenge_answer.setText("");

            dropdownChoose.getItems().clear();
            dropdownChoose.getItems().addAll(cipherResponse);

            dropdownChoose.getSelectionModel().selectedIndexProperty().addListener(changeListener);
            dropdownChoose.setValue("Escolher Cifra");
            challenge_answer.setDisable(true);
        }else{
            dropdownChoose.getSelectionModel().selectedIndexProperty().removeListener(changeListener);
            challenge_content.setText("");
            challenge_tips.setText("");
            challenge_answer.setText("");
            dropdownChoose.getItems().clear();
            dropdownChoose.setDisable(true);
            challenge_answer.setDisable(true);
        }
    }

    //when user chooses type "Hash"
    public void hashChoose_resolve(){
        if(hashResponse.size() != 0) {
            dropdownChoose.setDisable(false);
            challenge_answer.setDisable(false);

            dropdownChoose.getSelectionModel().selectedIndexProperty().removeListener(changeListener);
            challenge_content.setText("");
            challenge_answer.setText("");
            challenge_tips.setText("");

            dropdownChoose.getItems().clear();
            dropdownChoose.getItems().addAll(hashResponse);

            dropdownChoose.getSelectionModel().selectedIndexProperty().addListener(changeListener);
            dropdownChoose.setValue("Escolher Hash");
            challenge_answer.setDisable(true);
        }else{
            dropdownChoose.getSelectionModel().selectedIndexProperty().removeListener(changeListener);
            challenge_content.setText("");
            challenge_tips.setText("");
            challenge_answer.setText("");
            dropdownChoose.getItems().clear();
            dropdownChoose.setDisable(true);
            challenge_answer.setDisable(true);
        }
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
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(fxmlLoader.load(),600,400);
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();

        //instantiate elements of fxml
        textCredentials = (Text) fxmlLoader.getNamespace().get("textCredentials");
        emailInput = (TextField) fxmlLoader.getNamespace().get("emailInput");
        passwordInput = (PasswordField) fxmlLoader.getNamespace().get("passwordInput");
        submit = (Button) fxmlLoader.getNamespace().get("submit");
        cancelButtonCredentials = (Button) fxmlLoader.getNamespace().get("cancelButtonCredentials");

        //warning server if user choosed login or register
        login_access = true;
        email_Valid = false;
        listenerElementsCredentialsMenu();
    }

    public void switchCredentialsMenuRegister(ActionEvent event) throws IOException{
        //stage switching and creation
        FXMLLoader fxmlLoader = new FXMLLoader(Client.class.getResource("credentials_client_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(fxmlLoader.load(),600,400);
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();

        //instantiate elements of fxml
        textCredentials = (Text) fxmlLoader.getNamespace().get("textCredentials");
        emailInput = (TextField) fxmlLoader.getNamespace().get("emailInput");
        passwordInput = (PasswordField) fxmlLoader.getNamespace().get("passwordInput");
        submit = (Button) fxmlLoader.getNamespace().get("submit");
        cancelButtonCredentials = (Button) fxmlLoader.getNamespace().get("cancelButtonCredentials");
        email_Valid = false;
        listenerElementsCredentialsMenu();
    }

    public void switchMainMenu(ActionEvent event) throws IOException{
        //stage switching and creation
        root = FXMLLoader.load(Client.class.getResource("main_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root,600,400);
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
        scene = new Scene(root,600,400);
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
        scene = new Scene(root,600,400);
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
        scene = new Scene(root,600,400);
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
            FXMLLoader loader = new FXMLLoader(Client.class.getResource("resolve_challenge.fxml"));

            stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
            scene = new Scene(loader.load(),600,400);
            stage.setMinWidth(600);
            stage.setMinHeight(400);
            stage.setScene(scene);

            dropdownTypeChoose = (ChoiceBox) loader.getNamespace().get("dropdownTypeChoose");
            dropdownChoose = (ChoiceBox) loader.getNamespace().get("dropdownChoose");
            challenge_content = (Text) loader.getNamespace().get("challenge_content");
            challenge_tips = (Text) loader.getNamespace().get("challenge_tips");
            challenge_answer = (TextField) loader.getNamespace().get("challenge_answer");

            insertButtonChoose = (Button) loader.getNamespace().get("insertButtonChoose");
            cancelButtonChoose = (Button) loader.getNamespace().get("cancelButtonChoose");

            typeText = (Text) loader.getNamespace().get("typeText");
            challenge_content_text = (Text) loader.getNamespace().get("challenge_content_text");
            challenge_tips_text = (Text) loader.getNamespace().get("challenge_tips_text");
            challenge_answer_text = (Text) loader.getNamespace().get("challenge_answer_text");

            title_resolve = (Text) loader.getNamespace().get("title_resolve");

            dropdownTypeChoose.getItems().add("Cifra");
            dropdownTypeChoose.getItems().add("Hash");

            dropdownTypeChoose.setValue("Tipo de Desafio");
            stage.show();

            controlResolveElements();


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

    //function to verify result of challenges
    public void verifyResponsesResolve(ActionEvent event){
        try {
            byte[] typeResponse = (byte[]) Client.is.readObject();
            byte[] typeResponseHash = (byte[]) Client.is.readObject();

            String decipheredtypeResponse = CipherDecipherClient.decrypt(typeResponse,Client.server_client,"AES",null);
            String decipheredtypeResponseHash = CipherDecipherClient.decrypt(typeResponseHash,Client.server_client_hash,"AES",null);

            if(decipheredtypeResponse.equals("success")){
                byte[] plaintextResponse = (byte[]) Client.is.readObject();
                byte[] plaintextResponseHash = (byte[]) Client.is.readObject();

                String decipheredplaintextResponse = CipherDecipherClient.decrypt(plaintextResponse,Client.server_client,"AES",null);
                String decipheredplaintextResponseHash = CipherDecipherClient.decrypt(plaintextResponseHash,Client.server_client_hash,"AES",null);
                try {
                    PopoutEmptyLists.display("Sucesso!","Acertou o desafio! A solução é: " + decipheredplaintextResponse);
                    switchMainMenu(event);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }else{
                try {
                    PopoutEmptyLists.display("Incorreto!","Errou o desafio! Volte a tentar!");
                } catch (Exception e) {
                    e.printStackTrace();
                }
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