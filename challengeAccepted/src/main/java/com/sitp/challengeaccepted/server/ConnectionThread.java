package com.sitp.challengeaccepted.server;

import com.sitp.challengeaccepted.server.keysClasses.ConnectionKeys;
import com.sitp.challengeaccepted.server.keysClasses.PrivateKeyReader;
import com.sitp.challengeaccepted.server.keysClasses.PublicKeyReader;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Objects;

public class ConnectionThread extends Thread {
    private Socket S;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private ObjectInputStream is;
    private ObjectOutputStream os;
    private ByteArrayInputStream bis;
    private ByteArrayOutputStream bos;
    private ConnectionKeys connectionKeys;
    private String decipheredTypeOfOperation;
    private String decipheredTypeOfOperationHash;
    private  byte [] typeOfOperation;
    private  byte [] typeOfOperationHash;

    public ConnectionThread(Socket S){
        super();
        System.out.println("New connection!");
        this.S = S;
        connectionKeys = new ConnectionKeys();
        start();
    }

    public void run(){
        generatePrivatePublicKeys();
        sendPublicKeyToClient();
        receiveConnectionKeys();
        while(true){
            clientOperations();
        }
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
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private void InputStreams(){
        is = null;
        os = null;
        bis = null;
        bos = null;
        try {
            is = new ObjectInputStream(S.getInputStream());
            os = new ObjectOutputStream(S.getOutputStream());
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private void receiveConnectionKeys() {
        try {
            connectionKeys.setInfo_client_server(ConnectionKeys.generateKey(CipherDecipher.decrypt(is.readNBytes(128),privateKey)));
            connectionKeys.setInfo_client_server_hash(ConnectionKeys.generateKey(CipherDecipher.decrypt(is.readNBytes(128),privateKey)));
            connectionKeys.setInfo_server_client(ConnectionKeys.generateKey(CipherDecipher.decrypt(is.readNBytes(128),privateKey)));
            connectionKeys.setInfo_server_client_hash(ConnectionKeys.generateKey(CipherDecipher.decrypt(is.readNBytes(128),privateKey)));
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException e) {
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
            operationCase(getTypeOfOperation());
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

    private void registerOperation() {
        System.out.println("register method");
    }

    private void loginOperation() {
        System.out.println("login method");
        respondToClient();
    }

    private void respondToClient() {
        
    }

    private String getTypeOfOperation() {
        try {
            readOptionFromClient();
            decipherMessageAndHash();
        } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return checkHash();
    }

    private String checkHash() {
        if(getHash(decipheredTypeOfOperation).equals(decipheredTypeOfOperationHash)){
            return decipheredTypeOfOperation;
        }
        return null;
    }

    private void decipherMessageAndHash() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        decipheredTypeOfOperation = CipherDecipher.decrypt(typeOfOperation,connectionKeys.getInfo_client_server(),"AES",null);
        decipheredTypeOfOperationHash = CipherDecipher.decrypt(typeOfOperationHash,connectionKeys.getInfo_client_server_hash(),"AES",null);
    }

    private void readOptionFromClient() throws IOException, ClassNotFoundException {
        decipheredTypeOfOperation = null;
        decipheredTypeOfOperationHash = null;
        typeOfOperation = (byte[]) is.readObject();
        typeOfOperationHash = (byte[]) is.readObject();
    }

    private String getHash(String content){
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(content.getBytes());
            return new String(md.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
