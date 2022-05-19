package com.sitp.challengeaccepted.server;

import com.sitp.challengeaccepted.atributes.CipherChallengesAttributes;
import com.sitp.challengeaccepted.atributes.HashChallengesAttributes;
import com.sitp.challengeaccepted.server.challenges.CipherDecipherChallenges;
import com.sitp.challengeaccepted.server.challenges.GenerateValues;
import com.sitp.challengeaccepted.server.database.Database;
import com.sitp.challengeaccepted.server.database.Queries;
import com.sitp.challengeaccepted.server.keysClasses.ConnectionKeys;
import com.sitp.challengeaccepted.server.keysClasses.PrivateKeyReader;
import com.sitp.challengeaccepted.server.keysClasses.PublicKeyReader;
import com.sitp.challengeaccepted.server.keysClasses.SymmetricKeyReader;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.sql.Array;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;

public class ConnectionThread extends Thread {
    private final Socket S;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private PublicKey signaturePublicKey;
    private PrivateKey signaturePrivateKey;
    private SecretKey adminSecretKey;
    private ObjectInputStream is;
    private ObjectOutputStream os;
    private final ConnectionKeys connectionKeys;
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
    }



    /**
     * Generates public and private keys
     */
    private void generatePrivatePublicKeys() {
        try {
            publicKey = PublicKeyReader.get("src/main/java/com/sitp/challengeaccepted/server/keys/publickey.der");
        } catch (Exception e) {
            e.printStackTrace();
            Thread.currentThread().stop();
        }
        try {
            privateKey = PrivateKeyReader.get("src/main/java/com/sitp/challengeaccepted/server/keys/privatekey.der");
        } catch (Exception e) {
            e.printStackTrace();
            Thread.currentThread().stop();
        }
        try {
            signaturePublicKey = PublicKeyReader.get("src/main/java/com/sitp/challengeaccepted/server/keys/signaturepublickey.der");
        } catch (Exception e) {
            e.printStackTrace();
            Thread.currentThread().stop();
        }
        try {
            signaturePrivateKey = PrivateKeyReader.get("src/main/java/com/sitp/challengeaccepted/server/keys/signatureprivatekey.der");
        } catch (Exception e) {
            e.printStackTrace();
            Thread.currentThread().stop();
        }
        try {
            adminSecretKey = SymmetricKeyReader.get("InacioWillNeverKnow","ShameIfH371nd5!?".getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            Thread.currentThread().stop();
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
            Thread.currentThread().stop();
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
            Thread.currentThread().stop();
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
    }

    private void clientOperations() {
            operationCase(finalDecipheredMessage());
    }

    private void operationCase(String operation) {
        userLoggedIn = new User();
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
        respondToClientLogin();
    }

    private void respondToClientLogin() {
        String email = finalDecipheredMessage();
        byte[] saltedPassword = CipherDecipher.getSaltToPassword("One1Mor3E4ster6g9".getBytes(),finalDecipheredMessage());
        if(saltedPassword != null && loginVerification(email,new String(saltedPassword))){
            sendLogInStatusToClient("true");
            System.out.println("Log in success");
            operationMenu();
        }else{
            System.out.println("Log in failed");
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

    /**
     * Register operations
     */
    private void registerOperation() {
        respondToClientRegister();
    }

    private void respondToClientRegister() {
        String email = finalDecipheredMessage();
        byte[] saltedPassword = CipherDecipher.getSaltToPassword("One1Mor3E4ster6g9".getBytes(),finalDecipheredMessage());
        if(saltedPassword != null && registerVerification(email,new String(saltedPassword))){
            System.out.println("Register suc");
            sendLogInStatusToClient("true");
            operationMenu();
        }else{
            System.out.println("Register failed");
            sendLogInStatusToClient("false");
        }
    }

    private boolean registerVerification(String email, String password) {
        try {
            ResultSet resultSet = databaseCaller.getStatement().executeQuery(Queries.loginUser(email));
            if(resultSet.next())
               return false;
            databaseCaller.getStatement().executeUpdate(Queries.registerUser(email,password));
            ResultSet resultSet2 = databaseCaller.getStatement().executeQuery(Queries.loginUser(email));
            resultSet2.next();
            userLoggedIn = new User();
            userLoggedIn.setUser_id(resultSet2.getInt(1));
            userLoggedIn.setEmail(resultSet2.getString(2));
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * Menu
     */
    private void operationMenu() {
        String option;
        while (true) {
            System.out.println("Option:");
            option = finalDecipheredMessage();
            System.out.println(option);
            switch (option) {
                case "create":
                    if (createChallenge()) {
                        sendLogInStatusToClient("true");
                    } else {
                        sendLogInStatusToClient("false");
                    }
                    break;
                case "resolve":
                    if (!sendChallengesList()) {
                        break;
                    }
                    resolveChallenge();
                    break;
                case "logout":
                    return;
            }
        }

    }



    /**
     * Ciphers and hashes
     */
    private boolean createChallenge () {
        String challengeType = finalDecipheredMessage();
        //System.out.println("challengetype:"+challengeType);
        return switch (challengeType) {
            case "Cifra" -> createCipherChallenge();
            case "Hash" -> createHashChallenge();
            default -> false;
        };
    }

    private boolean createCipherChallenge () {
        String challengeSpecification = finalDecipheredMessage();
        String message = finalDecipheredMessage();
        String tips="";
        if(!challengeSpecification.equals("ELGAMAL")){
            tips = finalDecipheredMessage();
        }

        byte[] salt = null;
        byte[] iv = null;
        IvParameterSpec ivVector=null;
        String cipherText=null;

        // CIPHER OPERATION
        if(challengeSpecification.contains("AES")){
            salt = GenerateValues.getSalt();
            if(challengeSpecification.contains("CBC") || challengeSpecification.contains("CTR")){
                iv= GenerateValues.getIvVector();
                if (iv != null) {
                    ivVector = new IvParameterSpec(iv);
                }
            }
        }

        if(challengeSpecification.equals("ELGAMAL")){
            ArrayList<String> valuesReturned = CipherDecipherChallenges.encryptElGamal(message, finalDecipheredMessage());
            if(valuesReturned!=null){
                cipherText = valuesReturned.get(0);
                tips = valuesReturned.get(1);
                System.out.println(cipherText);
            }
        }else if(!challengeSpecification.equals("CESAR")){
            cipherText = CipherDecipherChallenges.encryptCipher(challengeSpecification, message, finalDecipheredMessage(), salt, ivVector);
        }
        else{
            // Password in the case of cesar's cipher is a offset
            cipherText = CipherDecipherChallenges.encryptCesar(message.toUpperCase(), Integer.parseInt(finalDecipheredMessage()));
        }

        String hmac = GenerateValues.doHMACMessage(message,adminSecretKey);
        String signature = GenerateValues.signMessage(message, signaturePrivateKey);
        String cryptogram = cipherText;

        ResultSet checkHMAC = null;
        try {
            checkHMAC = databaseCaller.getStatement().executeQuery(Queries.checkHMAC(hmac,challengeSpecification));
        } catch (SQLException e) {
            e.printStackTrace();
        }
        try {
            assert checkHMAC != null;
            if (checkHMAC.next())
                return false;
        } catch (SQLException e) {
            e.printStackTrace();
        }


        try {
            PreparedStatement ps = databaseCaller.getConnection().prepareStatement(Queries.createCipherChallenge());
            //"VALUES (" + user.getUser_id() + ", '" + challengeSpecification + "', '" + hmac + "', '" + cryptogram + "', '" + iv + "', '" + salt + "', '" + tips + "');";
            ps.setInt(1,userLoggedIn.getUser_id());
            ps.setString(2,challengeSpecification);
            ps.setString(3,hmac);
            ps.setString(4,cryptogram);
            ps.setBytes(5,iv);
            ps.setBytes(6,salt);
            ps.setString(7,tips);
            ps.setString(8, signature);
            System.out.println(ps.execute());
            return true;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    private boolean createHashChallenge () {
        String challengeSpecification = finalDecipheredMessage();
        String message = CipherDecipherChallenges.CreateHash(challengeSpecification,finalDecipheredMessage());
        String tips = finalDecipheredMessage();
        try {
            ResultSet checkHash = databaseCaller.getStatement().executeQuery(Queries.checkHash(message));
            if (checkHash.next())
                return false;
            else {
                databaseCaller.getStatement().executeUpdate(Queries.createHashChallenge(userLoggedIn, challengeSpecification, message, tips));
                return true;
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    private void resolveChallenge() {
        String challengeType;
         do{
            System.out.println("ChallengeType:");
             challengeType = finalDecipheredMessage();
            System.out.println(challengeType);
            switch (challengeType) {
                case "Cifra":
                    if(resolveCipherChallenge())
                        return;
                    break;
                case "Hash":
                    if(resolveHashChallenge())
                        return;
                    break;
                default:
                    return;
            }
        }while (true);
    }

    private boolean resolveCipherChallenge(){
        System.out.println("Cipher resolving");
        String id = finalDecipheredMessage();
        String password = finalDecipheredMessage();
        String specification, hmac, message, signature, plaintext = "";
        byte [] salt, iv;
        try {
            ResultSet challengeData = databaseCaller.getStatement().executeQuery(Queries.getCipherChallengeData(id));
            challengeData.next();
            specification = challengeData.getString(1);
            hmac = challengeData.getString(2);
            message = challengeData.getString(3);
            iv = challengeData.getBytes(4);
            salt = challengeData.getBytes(5);
            signature = challengeData.getString(6);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        if (iv != null && !specification.equals("CESAR")) {
            plaintext = CipherDecipherChallenges.decryptCipher(specification, message, password, salt, new IvParameterSpec(iv));
        } else if (!specification.equals("CESAR")) {
            plaintext = CipherDecipherChallenges.decryptCipher(specification, message, password, salt, null);
        } else {
            plaintext = CipherDecipherChallenges.decryptCesar(message, Integer.parseInt(password));
        }
        System.out.println("Plaintext");
        System.out.println(plaintext);
        if (plaintext != null) {
            String hmacPlaintext = GenerateValues.doHMACMessage(plaintext, adminSecretKey);
            boolean verify = GenerateValues.verifySignature(plaintext, signature, signaturePublicKey);

            if(hmac.equals(hmacPlaintext))
                System.out.println("Hmac is equal");
            if(verify)
                System.out.println("Signature is equal");

            if (hmac.equals(hmacPlaintext) && verify) {
                System.out.println("good decipher");
                sendLogInStatusToClient("success");
                sendLogInStatusToClient(plaintext);

                try {
                    databaseCaller.getStatement().executeUpdate(Queries.resolvedCipher(String.valueOf(userLoggedIn.getUser_id()),id));
                } catch (SQLException e) {
                    throw new RuntimeException(e);
                }
                return true;
            } else {
                System.out.println("bad decipher");
                sendLogInStatusToClient("fail");
            }
        }else {
            sendLogInStatusToClient("fail");
        }
        return false;
    }

    private boolean resolveHashChallenge() {
        String id = finalDecipheredMessage();
        String password = finalDecipheredMessage();
        String specification, hash, result = "";
        try {
            ResultSet challengeData = databaseCaller.getStatement().executeQuery(Queries.getHashChallengeData(id));
            challengeData.next();
            specification = challengeData.getString(1);
            hash = challengeData.getString(2);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        result = CipherDecipherChallenges.CreateHash(specification, password);
        if (result.equals(hash)) {
            System.out.println("good hash");
            sendLogInStatusToClient("sucess");
            return true;
        } else {
            System.out.println("bad hash");
            sendLogInStatusToClient("fail");
        }
        return false;
    }

    private boolean sendChallengesList() {
        boolean cipher = false, hash = false;
        ArrayList<CipherChallengesAttributes> cipherChallengesList = ciphersFromDatabase(userLoggedIn.getUser_id());
        ArrayList<HashChallengesAttributes> hashChallengesList = hashFromDatabase(userLoggedIn.getUser_id());
        cipher = checkChallengesList(cipherChallengesList, "cipher");
        hash = checkChallengesList(hashChallengesList, "hash");
        if (cipher) {
            sendListToClient(cipherChallengesList);
        }
        if (hash) {
            sendListToClient(hashChallengesList);
        }
        return cipher || hash;
    }

    private boolean checkChallengesList (ArrayList<?> challengesList, String type) {
        if (challengesList.size() == 0) {
            sendLogInStatusToClient("empty");
            return false;
        } else {
            sendLogInStatusToClient(type);
            return true;
        }
    }

    private void sendListToClient(ArrayList<?> challengesList) {
        try {
            cipherMessageAndHash(challengesList,"AES",null);
            writeCipheredToClient(cipheredMessage);
            writeCipheredToClient(cipheredMessageHash);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | IOException e) {
            e.printStackTrace();
        }
    }

    private ArrayList<CipherChallengesAttributes> ciphersFromDatabase(int user_id) {
        ArrayList<CipherChallengesAttributes> cipherChallengesList = new ArrayList<>();
        ResultSet ciphersCaller;
        try {
            ciphersCaller = databaseCaller.getStatement().executeQuery(Queries.challengesCipherList(String.valueOf(user_id)));
            if(!ciphersCaller.next())
                System.out.println("No ciphers available");
            else
            do {

                int challengeId = ciphersCaller.getInt(1);
                String type_cipher = ciphersCaller.getString(2);
                String cipher_message = ciphersCaller.getString(3);
                String cipher_tips = ciphersCaller.getString(4);
                cipherChallengesList.add(new CipherChallengesAttributes(challengeId,type_cipher,cipher_message,cipher_tips));
            } while (ciphersCaller.next());
            System.out.println("Has value: " + cipherChallengesList.size());
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return cipherChallengesList;
    }

    private ArrayList<HashChallengesAttributes> hashFromDatabase(int user_id) {
        ArrayList<HashChallengesAttributes> hashChallengesList = new ArrayList<>();
        ResultSet hashCaller;
        try{
            hashCaller = databaseCaller.getStatement().executeQuery(Queries.challengesHashList(String.valueOf(user_id)));
            if(!hashCaller.next())
                System.out.println("No hashs available");
            else
            do {
                int hash_id = hashCaller.getInt(1);
                String hash_specification = hashCaller.getString(2);
                String hash_hash = hashCaller.getString(3);
                String hash_tips = hashCaller.getString(4);
                hashChallengesList.add(new HashChallengesAttributes(hash_id,hash_specification,hash_hash,hash_tips));
            }while (hashCaller.next());
            System.out.println("Has value: " + hashChallengesList.size());
        }catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return hashChallengesList;
    }

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
            Thread.currentThread().stop();
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

    private void cipherMessageAndHash(ArrayList<?> data,String cipherAlgorithm, IvParameterSpec iv) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException {
        cipheredMessage = CipherDecipher.encrypt(data,connectionKeys.getInfo_server_client(),cipherAlgorithm,iv);
        cipheredMessageHash = CipherDecipher.encrypt(getHash(data,"SHA-256"),connectionKeys.getInfo_server_client_hash(),cipherAlgorithm,iv);
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

    private String getHash(ArrayList<?> content, String hashAlgorithm){
        if(content == null)
            return null;
        try{
            MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
            md.update(CipherDecipher.bytesFromArrayList(content));
            return new String(md.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
