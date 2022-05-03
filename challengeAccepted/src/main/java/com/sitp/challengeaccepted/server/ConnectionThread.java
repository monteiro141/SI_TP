package com.sitp.challengeaccepted.server;

import com.sitp.challengeaccepted.server.keysClasses.ConnectionKeys;
import com.sitp.challengeaccepted.server.keysClasses.PrivateKeyReader;
import com.sitp.challengeaccepted.server.keysClasses.PublicKeyReader;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.*;

public class ConnectionThread extends Thread {
    private Socket S;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private ObjectInputStream is;
    private ObjectOutputStream os;
    private ConnectionKeys connectionKeys;

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
        //clientOperations();
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
            System.out.println(e.getMessage());
        }
        System.out.println(connectionKeys.toString());
    }

    private void clientOperations() {
        String operation;
        while(true){
            if((operation = getTypeOfOperation()) == null){
                return;
            }
            switch (operation){
                case "login":
                    System.out.println("login method");
                    break;
                case "register":
                    System.out.println("register method");
                    break;
                default:
                    System.out.println("no method");
            }
        }

    }

    private String getTypeOfOperation() {
        try {
            return (String) is.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.out.println(e.getMessage());
        }
        return null;
    }
}
