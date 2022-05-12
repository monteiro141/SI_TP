package com.sitp.challengeaccepted.server;

import com.sitp.challengeaccepted.server.keysClasses.ConnectionKeys;
import com.sitp.challengeaccepted.server.keysClasses.PrivateKeyReader;
import com.sitp.challengeaccepted.server.keysClasses.PublicKeyReader;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.security.*;

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

    private void registerOperation() {
        System.out.println("register method");
        respondToClient();
    }

    private void loginOperation() {
        System.out.println("login method");
        respondToClient();
        loginVerification();
    }

    private void loginVerification() {
        
    }

    private void respondToClient() {
        String email = finalDecipheredMessage();
        String password = finalDecipheredMessage();
        System.out.println(email);
        System.out.println(password);

    }
    private String finalDecipheredMessage() {
        try {
            readCipheredFromClient();
            decipherMessageAndHash("AES",null);
        } catch (IOException | ClassNotFoundException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
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

    private void readCipheredFromClient() throws IOException, ClassNotFoundException {
        cipheredMessage = (byte[]) is.readObject();
        cipheredMessageHash = (byte[]) is.readObject();
    }

    private String getHash(String content, String hashAlgorithm){
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
