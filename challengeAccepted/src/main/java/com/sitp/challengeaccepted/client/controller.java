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
import javafx.scene.image.Image;
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

    String imagePath = "file:src/main/resources/com/sitp/challengeaccepted/client/cyber-security.png";

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

    /**
     * function to submit login or register data to server , as well if user did login or register
     * @param event action event for button "submeter" in credentials_client_menu.fxml
     */

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

    /**
     * listener for email input in credentials menu of the application
     */
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

    /**
     * regex to verify if the email introduced by the user is valid or not
     * @param message message to apply regex on
     * @return boolean value (true if verifies or false if not)
     */
    public boolean verifyCredentialEmail(String message){
        if (message.matches("^(.+)@(.+)$")) {
            return true;
        }
        return false;
    }

    /**
     * function that groups important initial functions when starting application
     * @throws NoSuchPaddingException
     * @throws IOException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws ClassNotFoundException
     */
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

    //Group 4 - Elements of create challenge menu => create_challenge.fxml
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

    /**
     * function to apply changes on interface when choosing a cipher challenge in challenge menu
     * @param event action event to register input by user on the choice
     */

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

    /**
     * function to apply changes on interface when choosing a hash challenge in challenge menu
     * @param event action event to register input by user on the choice
     */

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

    //GROUP REGEX
    /**
     * regex to verify if message introduced by user is valid by Cesar and/or Vigenere standards
     * @param message message to apply regex on
     * @return boolean (true if verifies or false if not)
     */
    public boolean verifyMessageVigCes(String message){
        if (message.matches("[A-Z\s]+$")) {
            return true;
        }
        return false;
    }

    /**
     * regex to verify if message introduced by user is valid by AES standards
     * @param message message to apply regex on
     * @return boolean (true if verifies or false if not)
     */
    public boolean verifyAESMessageRegex(String message){
        if(message.matches("^[ -~]*$")){
            return true;
        }
        return false;
    }

    /**
     * regex to verify if offset (answer introduced by user in resolve_challenge.fxml in Cesar challenge) is between 1 and 25
     * @param message message to apply regex on
     * @return boolean (true if verifies or false if not)
     */
    public boolean verifyOffSetCesar(String message){
        if(message.matches("^([1-9]|1[0-9]|2[0-5])$")){
            return true;
        }
        return false;
    }

    /**
     * regex to verify if message and tips lengths don't get over the 128 characters limit (fields in create_challenge.fxml)
     * @param message message to apply regex on
     * @param tips message to apply regex on
     * @return boolean (true if verifies or false if not)
     */
    public boolean verify128CharsElements(String message, String tips){
        if(message.length() <= 128 && tips.length() <= 128) {
            return true;
        }
        return false;
    }

    /**
     * regex to verify if answer (in case of ElGamal challenge in resolve_challenge.fxml) is valid
     * @param message message to apply regex on
     * @return boolean (true if verifies or false if not)
     */
    public boolean verifyElGamal(String message){
        if(message.matches("([2-9]|[12][0-9])")){
            return true;
        }
        return false;
    }

    //END GROUP REGEX -------------------------------

    /**
     * function with listeners to perform changes in interface create_challenge.fxml when user chooses type of challenge (hash or cipher)
     */
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
                passInsertText.setText("y (1 < y < (31-1)):");
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

    /**
     * function to send information (type of challenge, challenge mode, message, tips, password) introduced by user in create challenge menu to the server side
     * @param event action event to handle user input
     */
    public void insertButtonInput(ActionEvent event){
        try {
            byte[] sendTypeChallenge = CipherDecipherClient.encrypt(dropdownTypeChallenge.getText(),Client.client_server,"AES",null);
            byte[] sendTypeChallengeHash = CipherDecipherClient.encrypt(CipherDecipherClient.doHMACMessage(dropdownTypeChallenge.getText(),Client.client_server_hash),Client.client_server_hash,"AES",null);

            byte[] sendType = CipherDecipherClient.encrypt(dropdownTypes.getValue(), Client.client_server,"AES",null);
            byte[] sendTypeHash = CipherDecipherClient.encrypt(CipherDecipherClient.doHMACMessage(dropdownTypes.getValue(),Client.client_server_hash), Client.client_server_hash,"AES",null);

            byte[] sendMessage = CipherDecipherClient.encrypt(messageInsert.getText(),Client.client_server,"AES",null);
            byte[] sendMessageHash = CipherDecipherClient.encrypt(CipherDecipherClient.doHMACMessage(messageInsert.getText(),Client.client_server_hash),Client.client_server_hash,"AES",null);


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
                byte[] sendTipsHash = CipherDecipherClient.encrypt(CipherDecipherClient.doHMACMessage(tips.getText(),Client.client_server_hash),Client.client_server_hash,"AES",null);
                Client.os.writeObject(sendTips);
                Client.os.writeObject(sendTipsHash);
                Client.os.flush();
            }

            //type chosen is not hash
            if(!passInsert.isDisable()) {
                byte[] sendPassword = CipherDecipherClient.encrypt(passInsert.getText(), Client.client_server, "AES", null);
                byte[] sendPasswordHash = CipherDecipherClient.encrypt(CipherDecipherClient.doHMACMessage(passInsert.getText(),Client.client_server_hash), Client.client_server_hash, "AES", null);
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

    /**
     * function to handle information introduced by user in resolve_challenge.fxml and send it to the server side (sends type of challenge, id of the challenge and answer of the challenge)
     * @param event action event to handle user input
     */
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

    /**
     * function to send information to server side when user resolves a challenge
     * @param sent_data data to send to server side
     */
    public void sendResolveDataToServer(String sent_data){
        try{
            byte[] sendData = CipherDecipherClient.encrypt(sent_data,Client.client_server,"AES",null);
            byte[] sendData_Hash = CipherDecipherClient.encrypt(CipherDecipherClient.doHMACMessage(sent_data,Client.client_server_hash),Client.client_server_hash,"AES",null);

            Client.os.writeObject(sendData);
            Client.os.writeObject(sendData_Hash);
            Client.os.flush();
        } catch (NoSuchPaddingException | BadPaddingException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * function to perform changes on interface of resolve_challenge.fxml using listeners for each field
     */
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

            if(dropdownChoose.getValue().toString().toLowerCase().contains("vigenere") && !(challenge_answer.getText().equals(""))){
                if(verifyMessageVigCes(challenge_answer.getText()))
                    insertButtonChoose.setDisable(false);
                else
                    insertButtonChoose.setDisable(true);
            } else if(dropdownChoose.getValue().toString().toLowerCase().contains("cesar")){
                if(verifyOffSetCesar(challenge_answer.getText()))
                    insertButtonChoose.setDisable(false);
                else
                    insertButtonChoose.setDisable(true);
            } else if(dropdownChoose.getValue().toString().toLowerCase().contains("elgamal")){
                if(verifyElGamal(challenge_answer.getText()))
                    insertButtonChoose.setDisable(false);
                else
                    insertButtonChoose.setDisable(true);
            }else if(!(challenge_answer.getText().equals(""))){
                insertButtonChoose.setDisable(false);
            }else{
                insertButtonChoose.setDisable(true);
            }
        });

        dropdownChoose.showingProperty().addListener((observable, oldValue, newValue) ->{
            if(dropdownChoose.getValue().toString().toLowerCase().contains("cesar")) {
                challenge_answer_text.setText("Offset:");
                challenge_tips_text.setText("Dicas:");
            }
            else if(dropdownChoose.getValue().toString().toLowerCase().contains("elgamal")){
                challenge_tips_text.setText("Y:");
                challenge_answer_text.setText("x (1 < x < (31-1)):");
            }else if(dropdownChoose.getValue().toString().toLowerCase().contains("sha") || dropdownChoose.getValue().toString().toLowerCase().contains("md5")) {
                challenge_tips_text.setText("Dicas:");
                challenge_answer_text.setText("Mensagem:");
            }else if(!(dropdownChoose.getValue().toString().equals("Escolher"))) {
                challenge_answer_text.setText("Palavra Passe:");
                challenge_tips_text.setText("Dicas:");
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
                        challenge_content_text.setText("Criptograma:");
                        challenge_answer.setDisable(false);
                        break;
                    case "Hash":
                        if (hashResponse.size() == 0 || (int) newValue < 0)
                            break;
                        challenge_content.setText(hashResponse.get((int) newValue).getHash_hash());
                        challenge_tips.setText(hashResponse.get((int) newValue).getHash_tips());
                        challenge_content_text.setText("Hash:");
                        challenge_answer_text.setText("Mensagem:");
                        challenge_tips_text.setText("Dicas:");
                        challenge_answer.setDisable(false);
                        break;
                }
            }
        };
    }

    /**
     * function to perform changes on interface resolve_challenge.fxml according to type of challenge chosen (in this case Cipher challenge)
     */
    //when user chooses type "Cifra"
    public void cipherChoose_resolve(){
        if(cipherResponse.size() != 0) {
            dropdownChoose.setDisable(false);
            challenge_answer.setDisable(false);

            dropdownChoose.getSelectionModel().selectedIndexProperty().removeListener(changeListener);
            challenge_content.setText("");
            challenge_tips.setText("");
            challenge_answer.setText("");

            challenge_content_text.setText("Criptograma:");
            challenge_answer_text.setText("Palavra Passe:");
            challenge_tips_text.setText("Dicas:");

            dropdownChoose.getItems().clear();
            dropdownChoose.getItems().addAll(cipherResponse);

            dropdownChoose.getSelectionModel().selectedIndexProperty().addListener(changeListener);
            dropdownChoose.setValue("Escolher");
            challenge_answer.setDisable(true);
        }else{
            dropdownChoose.getSelectionModel().selectedIndexProperty().removeListener(changeListener);
            challenge_content.setText("");
            challenge_tips.setText("");
            challenge_answer.setText("");
            challenge_content_text.setText("Criptograma:");
            challenge_answer_text.setText("Palavra Passe:");
            challenge_tips_text.setText("Dicas:");
            dropdownChoose.getItems().clear();
            dropdownChoose.setDisable(true);
            challenge_answer.setDisable(true);
        }
    }

    /**
     * function to perform changes on interface resolve_challenge.fxml according to type of challenge chosen (in this case Hash challenge)
     */
    public void hashChoose_resolve(){
        if(hashResponse.size() != 0) {
            dropdownChoose.setDisable(false);
            challenge_answer.setDisable(false);

            dropdownChoose.getSelectionModel().selectedIndexProperty().removeListener(changeListener);
            challenge_content.setText("");
            challenge_answer.setText("");
            challenge_tips.setText("");

            challenge_content_text.setText("Hash:");
            challenge_answer_text.setText("Mensagem:");
            challenge_tips_text.setText("Dicas:");

            dropdownChoose.getItems().clear();
            dropdownChoose.getItems().addAll(hashResponse);

            dropdownChoose.getSelectionModel().selectedIndexProperty().addListener(changeListener);
            dropdownChoose.setValue("Escolher");
            challenge_answer.setDisable(true);
        }else{
            dropdownChoose.getSelectionModel().selectedIndexProperty().removeListener(changeListener);
            challenge_content.setText("");
            challenge_tips.setText("");
            challenge_answer.setText("");

            challenge_content_text.setText("Hash:");
            challenge_answer_text.setText("Mensagem:");
            challenge_tips_text.setText("Dicas:");

            dropdownChoose.getItems().clear();
            dropdownChoose.setDisable(true);
            challenge_answer.setDisable(true);
        }
    }
    //END GROUP 5 -------------------------------

    //Group Scenes - Functions to change scenes => to change fxml files (pages)

    /**
     * function to switch user to login_register_menu.fxml (initial menu page when application starts)
     * @param event action event to handle user input
     * @throws IOException
     */
    public void switchLoginMenu(ActionEvent event) throws IOException{

        login_access = false;

        //send operation "logout" to server
        sendOperationMethodstoServer("logout");

        root = FXMLLoader.load(Client.class.getResource("login_register_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root,600,400);
        stage.getIcons().add(new Image(imagePath));
        stage.setResizable(false);
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();
    }

    /**
     * function to switch user to credentials_client_menu.fxml (menu where user inputs his credentials)
     * @param event action event to handle user input
     * @throws IOException
     */
    public void switchCredentialsMenuLogin(ActionEvent event) throws IOException{
        //stage switching and creation
        FXMLLoader fxmlLoader = new FXMLLoader(Client.class.getResource("credentials_client_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(fxmlLoader.load(),600,400);
        stage.getIcons().add(new Image(imagePath));
        stage.setResizable(false);
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

    /**
     * function to switch user to credentials_client_menu.fxml (menu where user inputs his credentials)
     * @param event action event to handle user input
     * @throws IOException
     */
    public void switchCredentialsMenuRegister(ActionEvent event) throws IOException{
        //stage switching and creation
        FXMLLoader fxmlLoader = new FXMLLoader(Client.class.getResource("credentials_client_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(fxmlLoader.load(),600,400);
        stage.getIcons().add(new Image(imagePath));
        stage.setResizable(false);
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

    /**
     * function to switch user to main_menu.fxml (main page when user logins successfully)
     * @param event action event to handle user input
     * @throws IOException
     */
    public void switchMainMenu(ActionEvent event) throws IOException{
        //stage switching and creation
        root = FXMLLoader.load(Client.class.getResource("main_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root,600,400);
        stage.getIcons().add(new Image(imagePath));
        stage.setResizable(false);
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();
    }

    /**
     * function to switch user to main_menu.fxml (when user cancels operations in create challenge menu)
     * @param event action event to handle user input
     * @throws IOException
     */
    public void switchMainMenuCreateChallenge(ActionEvent event) throws IOException{

        //send operation "cancel" to server
        sendOperationMethodstoServer("cancel");

        verifyResponses();

        //stage switching and creation
        root = FXMLLoader.load(Client.class.getResource("main_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root,600,400);
        stage.getIcons().add(new Image(imagePath));
        stage.setResizable(false);
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();
    }

    /**
     * function to switch user to main_menu.fxml (when user cancels operations in resolve challenge menu)
     * @param event action event to handle user input
     * @throws IOException
     */
    public void switchMainMenuChooseChallenge(ActionEvent event) throws IOException{

        //send operation "cancel" to server
        sendOperationMethodstoServer("cancel");

        verifyResponses();

        //stage switching and creation
        root = FXMLLoader.load(Client.class.getResource("main_menu.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root,600,400);
        stage.getIcons().add(new Image(imagePath));
        stage.setResizable(false);
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();
    }

    /**
     * function to send operation chosen by user in main menu
     * @param data sends the type of operation chosen by user
     */
    public void sendOperationMethodstoServer(String data){
        try {
            byte [] sendOperationCreate = CipherDecipherClient.encrypt(data,Client.client_server,"AES",null);
            byte [] sendOperationCreateHash = CipherDecipherClient.encrypt(CipherDecipherClient.doHMACMessage(data,Client.client_server_hash),Client.client_server_hash,"AES",null);

            Client.os.writeObject(sendOperationCreate);
            Client.os.writeObject(sendOperationCreateHash);
            Client.os.flush();
        } catch (BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * function to switch user to create_challenge.fxml, in this case the create challenge menu (when user chooses to create a challenge in main menu)
     * @param event action event to handle user input
     * @throws IOException
     */
    public void switchCreateChallengeMenu(ActionEvent event) throws IOException{

        //send type of operation "create" to inform server that user has chosen to create a challenge
        sendOperationMethodstoServer("create");

        //stage switching and creation
        root = FXMLLoader.load(Client.class.getResource("create_challenge.fxml"));
        stage = (Stage) ((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root,600,400);
        stage.getIcons().add(new Image(imagePath));
        stage.setResizable(false);
        stage.setMinWidth(600);
        stage.setMinHeight(400);
        stage.setScene(scene);
        stage.show();
    }

    /**
     * function to switch user to resolve_challenge.fxml, in this case the resolve challenge menu (when user chooses to resolve a challenge in main menu)
     * @param event action event to handle user input
     * @throws IOException
     */
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
            stage.getIcons().add(new Image(imagePath));
            stage.setResizable(false);
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

    //Group 6 - Group of operations

    /**
     * function to generate 4 keys to exchange with server side (2 for communications client -> server and other 2 for communications server -> client)
     * @throws NoSuchAlgorithmException
     */
    private void generateKeys() throws NoSuchAlgorithmException {
        Client.client_server = generateKey("AES",128);
        Client.client_server_hash = generateKey("AES",128);
        Client.server_client = generateKey("AES",128);
        Client.server_client_hash = generateKey("AES",128);
    }

    /**
     * function to generate a secret key
     * @param cipher_mode type of cipher mode to be used to create the key
     * @param sizeKey size of the key to be determined
     * @throws NoSuchAlgorithmException
     */
    private static SecretKey generateKey(String cipher_mode, int sizeKey) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerated = KeyGenerator.getInstance(cipher_mode);
        keyGenerated.init(sizeKey);
        return keyGenerated.generateKey();
    }

    /**
     * function to initiate socket with server (connection with server) and respective input e output streams to handle data receiving and giving
     * @throws IOException
     */
    //function to initiate socket connection to server
    private void initiateSocket() throws IOException{
        Socket S = new Socket("127.0.0.1",1099);
        //Socket S = new Socket("6.tcp.eu.ngrok.io",12649);
        Client.os = new ObjectOutputStream(S.getOutputStream());
        Client.is = new ObjectInputStream(S.getInputStream());
    }

    /**
     * function to encrypt the 4 keys generated previously and send them to the server side
     * @param public_key_server key received by server side to encrypt the 4 keys created
     * @param send_server output stream used to send data to server
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws NoSuchPaddingException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     */
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

    /**
     * function to send to server side operation chosen (login or register operation) and credentials that were introduced by user in credentials menu
     * @param data operation chosen by user (login or register operation)
     * @throws NoSuchPaddingException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     */
    private void send_Login_Register(String data) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException {
        byte [] login_bytes = CipherDecipherClient.encrypt(data,Client.client_server,"AES",null);
        byte [] login_bytes_hash = CipherDecipherClient.encrypt(CipherDecipherClient.doHMACMessage(data,Client.client_server_hash),Client.client_server_hash,"AES",null);

        byte [] email_bytes = CipherDecipherClient.encrypt(emailInput.getText(),Client.client_server,"AES",null);
        byte [] email_hash_bytes = CipherDecipherClient.encrypt(CipherDecipherClient.doHMACMessage(emailInput.getText(),Client.client_server_hash),Client.client_server_hash,"AES",null);

        byte [] password_bytes = CipherDecipherClient.encrypt(passwordInput.getText(),Client.client_server,"AES",null);
        byte [] password_hash_bytes = CipherDecipherClient.encrypt(CipherDecipherClient.doHMACMessage(passwordInput.getText(),Client.client_server_hash),Client.client_server_hash,"AES",null);

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

    /**
     * function to decrypt data received by server side regarding data when switching menus
     */
    public void verifyResponses(){
        try {
            byte[] typeResponse = (byte[]) Client.is.readObject();
            byte[] typeResponseHash = (byte[]) Client.is.readObject();

            String decipheredtypeResponse = CipherDecipherClient.decrypt(typeResponse,Client.server_client,"AES",null);
            String decipheredtypeResponseHash = CipherDecipherClient.decrypt(typeResponseHash,Client.server_client_hash,"AES",null);

            compareHmacsValidity(decipheredtypeResponse,decipheredtypeResponseHash);
        } catch (IOException | ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException | NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    /**
     * function to decrypt data received by server side and verify some status of operations chosen by the user
     * @param event action event to handle user input
     */
    public void verifyResponsesResolve(ActionEvent event){
        try {
            byte[] typeResponse = (byte[]) Client.is.readObject();
            byte[] typeResponseHash = (byte[]) Client.is.readObject();

            String decipheredtypeResponse = CipherDecipherClient.decrypt(typeResponse,Client.server_client,"AES",null);
            String decipheredtypeResponseHash = CipherDecipherClient.decrypt(typeResponseHash,Client.server_client_hash,"AES",null);

            compareHmacsValidity(decipheredtypeResponse,decipheredtypeResponseHash);

            if(decipheredtypeResponse.equals("success")){
                byte[] plaintextResponse = (byte[]) Client.is.readObject();
                byte[] plaintextResponseHash = (byte[]) Client.is.readObject();

                String decipheredplaintextResponse = CipherDecipherClient.decrypt(plaintextResponse,Client.server_client,"AES",null);
                String decipheredplaintextResponseHash = CipherDecipherClient.decrypt(plaintextResponseHash,Client.server_client_hash,"AES",null);

                compareHmacsValidity(decipheredplaintextResponse,decipheredplaintextResponseHash);

                try {
                    PopoutEmptyLists.display("Sucesso!","Acertou o desafio! A mensagem é: " + decipheredplaintextResponse);
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

    /**
     * function to receive arraylists of cipher and/or hash challenges sent by server side
     * @param option type of option chosen (cipher or hash)
     * @param responseSizeResponse content received through server side (determines if arraylist received is empty or not)
     * @param data array of bytes regarding content of response received by server side
     * @param dataHash array of bytes regarding content of hash response received by server side
     */
    public void receiveSizeLists(String option, String responseSizeResponse, byte[] data, byte[] dataHash){
        String response="";
        String responseHash="";

        switch (option){
            case "CIFRA":
                if(!(responseSizeResponse.equals("empty"))){
                    //receive first cipher challenges list
                    try {
                        data = (byte[]) Client.is.readObject();
                        dataHash = (byte[]) Client.is.readObject();

                        responseHash = CipherDecipherClient.decrypt(dataHash,Client.server_client_hash,"AES",null);
                    } catch (IOException | ClassNotFoundException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                        e.printStackTrace();
                    }

                    try {
                        cipherResponse = CipherDecipherClient.CipherdecryptLists(data, Client.server_client, "AES", null);
                        compareHmacsValidity(String.valueOf(cipherResponse),responseHash);
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
                        responseHash = CipherDecipherClient.decrypt(dataHash,Client.server_client_hash,"AES",null);
                    } catch (IOException | ClassNotFoundException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                        e.printStackTrace();
                    }

                    try {
                        hashResponse = CipherDecipherClient.HashdecryptLists(data, Client.server_client, "AES", null);
                        compareHmacsValidity(String.valueOf(hashResponse),responseHash);
                    } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                        e.printStackTrace();
                    }
                }else{
                    hashResponse = new ArrayList<>();
                }
                break;
        }
    }

    /**
     * function to verify size of lists of challenges received by server side
     * @return boolean (true if one of the lists is not empty or false if both are empty)
     */
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

            compareHmacsValidity(responseSizeResponse,responseSizeHashResponse);

            responseSizeResponseV2 = CipherDecipherClient.decrypt(responseSizeV2,Client.server_client,"AES",null);
            responseSizeHashResponseV2 = CipherDecipherClient.decrypt(responseSizeHashV2,Client.server_client_hash,"AES",null);

            compareHmacsValidity(responseSizeResponseV2,responseSizeHashResponseV2);

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
            return true;
        }
        return false;
    }

    /**
     * function to verify is the response sent by server is valid or not for creating challenge
     * @return boolean (true if challenge was created succesfully or false if not)
     */
    public boolean verifyResponsesValid(){
        try {
            byte[] typeResponse = (byte[]) Client.is.readObject();
            byte[] typeResponseHash = (byte[]) Client.is.readObject();

            String decipheredtypeResponse = CipherDecipherClient.decrypt(typeResponse,Client.server_client,"AES",null);
            String decipheredtypeResponseHash = CipherDecipherClient.decrypt(typeResponseHash,Client.server_client_hash,"AES",null);

            compareHmacsValidity(decipheredtypeResponse,decipheredtypeResponseHash);

            if(decipheredtypeResponse.equals("true")){
                return true;
            }

        } catch (IOException | ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException | NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * function to verify if user has performed a sucessfull login or not
     * @param event action event to handle user input
     */
    public void verifyLoginRegister(ActionEvent event) {
        try {
            byte[] statusResponse = (byte[]) Client.is.readObject();
            byte[] statusResponseHash = (byte[]) Client.is.readObject();

            String decipheredResponseStatus = CipherDecipherClient.decrypt(statusResponse, Client.server_client, "AES", null);
            String decipheredResponseStatusHash = CipherDecipherClient.decrypt(statusResponseHash, Client.server_client_hash, "AES", null);

            compareHmacsValidity(decipheredResponseStatus,decipheredResponseStatusHash);

            if(Boolean.parseBoolean(decipheredResponseStatus)){
                System.out.println("Login bem sucedido!");
                switchMainMenu(event);
            }else{
                textCredentials.setText("Credenciais incorretas!");
            }
        } catch (IOException | ClassNotFoundException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    /**
     * function to verify if the hmacs are the same or not (to prevent active man in the middle attack)
     * @param message message that was received by server side
     * @param hash_delivered hash received by server side
     */
    public void compareHmacsValidity(String message, String hash_delivered){
        //first recalculate HMAC
        String hash_recalculated = CipherDecipherClient.doHMACMessage(message,Client.server_client_hash);
        if(hash_recalculated.equals(hash_delivered)){
            System.out.println("Hmacs are the same!");
        }else{
            try {
                PopoutEmptyLists.display("Ligação não segura!","A terminar aplicação...");
            } catch (Exception e) {
                e.printStackTrace();
            }
            System.exit(0);
        }
    }
    // END GROUP 6 - Group of operations
}