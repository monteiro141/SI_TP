package com.sitp.challengeaccepted.server;

import com.sitp.challengeaccepted.server.database.Database;
import com.sitp.challengeaccepted.server.database.Queries;
import com.sitp.challengeaccepted.server.keysClasses.ConnectionKeys;
import com.sitp.challengeaccepted.server.keysClasses.PrivateKeyReader;
import com.sitp.challengeaccepted.server.keysClasses.PublicKeyReader;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.security.*;
import java.sql.ResultSet;
import java.sql.SQLException;

public class ConnectionThread extends Thread {
    private Socket S;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private ObjectInputStream is;
    private ObjectOutputStream os;
    private ConnectionKeys connectionKeys;
    private String decipheredMessage;
    private String decipheredMessageHash;
    private byte [] cipheredMessage;
    private byte [] cipheredMessageHash;
    private Database databaseCaller;
    private User userLoggedIn;

    public ConnectionThread(Socket S){
        super();
        System.out.println("New connection!");
        this.S = S;
        connectionKeys = new ConnectionKeys();
        try {
            start();
        }catch (Exception e){
            System.out.println("Socket shut down");
        }

    }

    public void run(){
        generatePrivatePublicKeys();
        sendPublicKeyToClient();
        receiveConnectionKeys();
        databaseCaller = new Database();
        if(databaseCaller.ConnectToDatabase())
        {
            while(true){
                clientOperations();
            }
        }
        EndThread:
        System.out.println();
    }



    /**
     * Generates public and private keys
     */
    private void generatePrivatePublicKeys() {
        try {
            publicKey = PublicKeyReader.get("src/main/java/com/sitp/challengeaccepted/server/keys/publickey.der");
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            privateKey = PrivateKeyReader.get("src/main/java/com/sitp/challengeaccepted/server/keys/privatekey.der");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void sendPublicKeyToClient() {
        InputStreams();
        try {
            os.writeObject(publicKey);
            os.flush();
        }catch (SocketException e){
            Thread.currentThread().stop();
        }
        catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private void InputStreams(){
        is = null;
        os = null;
        try {
            is = new ObjectInputStream(S.getInputStream());
            os = new ObjectOutputStream(S.getOutputStream());
        }catch (SocketException e){
            Thread.currentThread().stop();
        }
        catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private void receiveConnectionKeys() {
        try {
            connectionKeys.setInfo_client_server(ConnectionKeys.generateKey(CipherDecipher.decrypt(is.readNBytes(128),privateKey)));
            connectionKeys.setInfo_client_server_hash(ConnectionKeys.generateKey(CipherDecipher.decrypt(is.readNBytes(128),privateKey)));
            connectionKeys.setInfo_server_client(ConnectionKeys.generateKey(CipherDecipher.decrypt(is.readNBytes(128),privateKey)));
            connectionKeys.setInfo_server_client_hash(ConnectionKeys.generateKey(CipherDecipher.decrypt(is.readNBytes(128),privateKey)));
        }catch (SocketException e){
            Thread.currentThread().stop();
        }
        catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException e) {
            e.printStackTrace();
        }
        /*System.out.println("Connection keys");
        System.out.println(connectionKeys.getInfo_client_server().toString());
        System.out.println(connectionKeys.getInfo_client_server_hash().toString());
        System.out.println(connectionKeys.getInfo_server_client().toString());
        System.out.println(connectionKeys.getInfo_server_client_hash().toString());
        System.out.println("End");
         */
    }

    private void clientOperations() {
            operationCase(finalDecipheredMessage());
    }


    private void operationCase(String operation) {
        switch (operation) {
            case "login": loginOperation();
                break;
            case "register": registerOperation();
                break;
            default:
                break;
        }
    }
    /**
     * Login operations
     */
    private void loginOperation() {
        System.out.println("login method");
        respondToClientLogin();
    }

    private void respondToClientLogin() {
        String email = finalDecipheredMessage();
        String password = finalDecipheredMessage();
        if(loginVerification(email,password)){
            System.out.println("Log in suc.");
            sendLogInStatusToClient("true");
        }else{
            System.out.println("Log in failed.");
            sendLogInStatusToClient("false");
        }
    }

    private void sendLogInStatusToClient(String status) {
        try {
            cipherMessageAndHash(status,"AES",null);
            writeCipheredToClient(cipheredMessage);
            writeCipheredToClient(cipheredMessageHash);
        } catch (BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Register operations
     */
    private void registerOperation() {
        System.out.println("register method");
        respondToClientRegister();
    }

    private void respondToClientRegister() {
        String email = finalDecipheredMessage();
        String password = finalDecipheredMessage();
        if(registerVerification(email,password)){
            System.out.println("Register suc");
            sendLogInStatusToClient("true");
        }else{
            System.out.println("Register failed");
            sendLogInStatusToClient("false");
        }
    }

    private boolean loginVerification(String email, String password) {
        try {
            ResultSet resultSet = databaseCaller.getStatement().executeQuery(Queries.loginUser(email,password));
            if(!resultSet.next())
                return false;
            userLoggedIn = new User();
            userLoggedIn.setUser_id(resultSet.getInt(1));
            userLoggedIn.setEmail(resultSet.getString(2));
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private boolean registerVerification(String email, String password) {
        try {
            ResultSet resultSet = databaseCaller.getStatement().executeQuery(Queries.loginUser(email));
            if(resultSet.next())
               return false;
            resultSet = databaseCaller.getStatement().executeQuery(Queries.registerUser(email,password));
            userLoggedIn = new User();
            userLoggedIn.setUser_id(resultSet.getInt(1));
            userLoggedIn.setEmail(resultSet.getString(2));
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * Ciphers and hashes
     */
    private String finalDecipheredMessage() {
        try {
            readCipheredFromClient();
            decipherMessageAndHash("AES",null);
        } catch (ClassNotFoundException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (SocketException e){
            Thread.currentThread().stop();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return checkHash();
    }

    private String checkHash() {
        if(getHash(decipheredMessage,"SHA-256").equals(decipheredMessageHash)){
            return decipheredMessage;
        }
        return null;
    }

    private void decipherMessageAndHash(String cipherAlgorithm, IvParameterSpec iv) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        decipheredMessage = CipherDecipher.decrypt(cipheredMessage,connectionKeys.getInfo_client_server(),cipherAlgorithm,iv);
        decipheredMessageHash = CipherDecipher.decrypt(cipheredMessageHash,connectionKeys.getInfo_client_server_hash(),cipherAlgorithm,iv);
    }

    private void cipherMessageAndHash(String data,String cipherAlgorithm, IvParameterSpec iv) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException {
        cipheredMessage = CipherDecipher.encrypt(data,connectionKeys.getInfo_server_client(),cipherAlgorithm,iv);
        cipheredMessageHash = CipherDecipher.encrypt(getHash(data,"SHA-256"),connectionKeys.getInfo_server_client_hash(),cipherAlgorithm,iv);
    }

    private void readCipheredFromClient() throws IOException, ClassNotFoundException {
        cipheredMessage = (byte[]) is.readObject();
        cipheredMessageHash = (byte[]) is.readObject();
    }

    private void writeCipheredToClient(byte [] data) throws IOException {
        os.writeObject(data);
        os.flush();
    }

    private String getHash(String content, String hashAlgorithm){
        if(content == null)
            return null;
        try{
            MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
            md.update(content.getBytes());
            return new String(md.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
