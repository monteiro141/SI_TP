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

    /**
     * Establishes the connection with the thread
     * @param S the Socket
     */
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

    /**
     * Send public key to client
     */
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

    /**
     * Establishes the connections between client and server
     */
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

    /**
     * Receive the connection keys
     */
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

    /**
     * wait for client decision on Login or Register and then redirect the user to the correct task
     */
    private void clientOperations() {
            operationCase(finalDecipheredMessage());
    }

    /**
     * Do the operations of login or register
     * @param operation the operation chosen by the client
     */
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

    /**
     * Respond to client if login is successful or not and redirect to the correct page
     */
    private void respondToClientLogin() {
        String email = finalDecipheredMessage();
        byte[]salt;
        try {
            ResultSet resultSet = databaseCaller.getStatement().executeQuery(Queries.getLoginSalt(email));
            if(!resultSet.next()){
                System.out.println("Log in failed");
                sendLogInStatusToClient("false");
                return;
            }
            salt = resultSet.getBytes(1);
        } catch (SQLException e) {
            e.printStackTrace();
            return;
        }
        byte[] saltedPassword = CipherDecipher.getSaltToPassword(salt,finalDecipheredMessage());
        if(saltedPassword != null && loginVerification(email,new String(saltedPassword))){
            sendLogInStatusToClient("true");
            System.out.println("Log in success");
            operationMenu();
        }else{
            System.out.println("Log in failed");
            sendLogInStatusToClient("false");
        }
    }

    /**
     * Send login status to client
     * @param status the status
     */
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
     * Verify if the login is successful or not from the database
     * @param email the email
     * @param password the password
     * @return true if login is successful or false if not
     */
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

    /**
     * Responds to client if register was successful or not
     */
    private void respondToClientRegister() {
        String email = finalDecipheredMessage();
        byte[] salt = GenerateValues.getSalt();
        byte[] saltedPassword = CipherDecipher.getSaltToPassword(salt,finalDecipheredMessage());
        if(saltedPassword != null && registerVerification(email,new String(saltedPassword), salt)){
            System.out.println("Register suc");
            sendLogInStatusToClient("true");
            operationMenu();
        }else{
            System.out.println("Register failed");
            sendLogInStatusToClient("false");
        }
    }

    /**
     * Verify if the user exists. If not the user is registered
     * @param email the email
     * @param password the password
     * @param salt the salt generated
     * @return true if registration is successfull or false if not
     */
    private boolean registerVerification(String email, String password, byte[]salt) {

        try {

            ResultSet resultSet = databaseCaller.getStatement().executeQuery(Queries.loginUser(email));
            if(resultSet.next())
               return false;
            PreparedStatement ps = databaseCaller.getConnection().prepareStatement(Queries.registerUser());
            ps.setString(1,email);
            ps.setString(2,password);
            ps.setBytes(3,salt);
            ps.execute();
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
     * Operations Menu: Create challenge; Resolve Challenge; Logout
     */
    private void operationMenu() {
        String option;
        while (true) {
            option = finalDecipheredMessage();
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
     * Function to create a challenge: Ciphers and hashes
     * @return true if successful or false if not
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

    /**
     * Create the cipher Challenge
     * @return true if the creation was successful or false if not
     */
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
                iv = valuesReturned.get(2).getBytes();
            }
        }else if(!challengeSpecification.equals("CESAR")){
            cipherText = CipherDecipherChallenges.encryptCipher(challengeSpecification, message, finalDecipheredMessage(), salt, ivVector);
        }
        else{
            // Password in the case of cesar's cipher is a offset
            cipherText = CipherDecipherChallenges.encryptCesar(message, Integer.parseInt(finalDecipheredMessage()));
        }

        //Do the HMAC and Signature
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

        // save the cipher challenge in the database
        try {
            PreparedStatement ps = databaseCaller.getConnection().prepareStatement(Queries.createCipherChallenge());
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

    /**
     * Create the hash Challenge
     * @return true if the creation was successful or false if not
     */
    private boolean createHashChallenge () {
        String challengeSpecification = finalDecipheredMessage();
        String message = CipherDecipherChallenges.CreateHash(challengeSpecification,finalDecipheredMessage());
        String tips = finalDecipheredMessage();
        try {
            //Check if it already exists
            ResultSet checkHash = databaseCaller.getStatement().executeQuery(Queries.checkHash(message));
            if (checkHash.next())
                return false;
            else {
                //Save the hash challenge in the database
                databaseCaller.getStatement().executeUpdate(Queries.createHashChallenge(userLoggedIn, challengeSpecification, message, tips));
                return true;
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Resolve challenge operations
     */
    private void resolveChallenge() {
        String challengeType;
         do{
             challengeType = finalDecipheredMessage();
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
                     sendLogInStatusToClient("true");
                     return;
             }
        }while (true);
    }

    /**
     * Resolve a cipher challenge
     * @return true if the solution was correct or false if not
     */
    private boolean resolveCipherChallenge(){
        System.out.println("Cipher resolving");
        String id = finalDecipheredMessage();
        String password = finalDecipheredMessage();
        String specification, hmac, message, signature, tips, plaintext = "";
        byte [] salt, iv;
        try {
            //Get the cipher challenge information from the database
            ResultSet challengeData = databaseCaller.getStatement().executeQuery(Queries.getCipherChallengeData(id));
            challengeData.next();
            specification = challengeData.getString(1);
            hmac = challengeData.getString(2);
            message = challengeData.getString(3);
            iv = challengeData.getBytes(4);
            salt = challengeData.getBytes(5);
            signature = challengeData.getString(6);
            tips = challengeData.getString(7);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        //Do the decipher methods
        if(specification.equals("ELGAMAL")){
            plaintext = CipherDecipherChallenges.decryptElGamal(message, password, tips, new String(iv));
        }else if (iv != null && !specification.equals("CESAR")) {
            plaintext = CipherDecipherChallenges.decryptCipher(specification, message, password, salt, new IvParameterSpec(iv));
        } else if (!specification.equals("CESAR")) {
            plaintext = CipherDecipherChallenges.decryptCipher(specification, message, password, salt, null);
        } else {
            plaintext = CipherDecipherChallenges.decryptCesar(message.toUpperCase(), Integer.parseInt(password));
        }

        if (plaintext != null) {
            //Check if the HMAC is equal and the signature is valid
            String hmacPlaintext = GenerateValues.doHMACMessage(plaintext, adminSecretKey);
            boolean verify = GenerateValues.verifySignature(plaintext, signature, signaturePublicKey);


            if (hmac.equals(hmacPlaintext) && verify) {
                //Send to client that the solution is correct
                sendLogInStatusToClient("success");
                sendLogInStatusToClient(plaintext);

                try {
                    databaseCaller.getStatement().executeUpdate(Queries.resolvedCipher(String.valueOf(userLoggedIn.getUser_id()),id));
                } catch (SQLException e) {
                    throw new RuntimeException(e);
                }
                return true;
            } else {
                //Send to client that the solution is wrong
                sendLogInStatusToClient("fail");
            }
        }else {
            sendLogInStatusToClient("fail");
        }
        return false;
    }

    /**
     * Resolve a hash challenge
     * @return true if the solution was correct or false if not
     */
    private boolean resolveHashChallenge() {
        String id = finalDecipheredMessage();
        String password = finalDecipheredMessage();
        String specification, hash, result = "";
        try {
            //Get the hash information from the database
            ResultSet challengeData = databaseCaller.getStatement().executeQuery(Queries.getHashChallengeData(id));
            challengeData.next();
            specification = challengeData.getString(1);
            hash = challengeData.getString(2);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        //Create the hash from the message inserted by the user
        result = CipherDecipherChallenges.CreateHash(specification, password);
        //Check if the hash is equal
        if (result.equals(hash)) {
            try {
                databaseCaller.getStatement().executeUpdate(Queries.resolvedHash(String.valueOf(userLoggedIn.getUser_id()),id));
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
            //Send to client that the answer was correct
            sendLogInStatusToClient("success");
            sendLogInStatusToClient(password);
            return true;
        } else {
            //Send to client that the answer was wrong
            sendLogInStatusToClient("fail");
        }
        return false;
    }

    /**
     * Send to the client the challenges list
     * @return true if that is some challenge of any type or false if not (needed for the server side)
     */
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

    /**
     * Check if the challenges list is empty or not to be handled and send to client the type or "empty"
     * @param challengesList the challenges list
     * @param type the type of challenge (cipher or hash)
     * @return true if not empty or false if empty
     */
    private boolean checkChallengesList (ArrayList<?> challengesList, String type) {
        if (challengesList.size() == 0) {
            sendLogInStatusToClient("empty");
            return false;
        } else {
            sendLogInStatusToClient(type);
            return true;
        }
    }

    /**
     * Send the arrayList with challenges to the client
     * @param challengesList the challenges list
     */
    private void sendListToClient(ArrayList<?> challengesList) {
        try {
            cipherMessageAndHash(challengesList,"AES",null);
            writeCipheredToClient(cipheredMessage);
            writeCipheredToClient(cipheredMessageHash);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Get the cipher challlenges attributes from database that a user didn't created and didn't solved
     * @param user_id the user id
     * @return the arrayList
     */
    private ArrayList<CipherChallengesAttributes> ciphersFromDatabase(int user_id) {
        ArrayList<CipherChallengesAttributes> cipherChallengesList = new ArrayList<>();
        ResultSet ciphersCaller;
        try {
            ciphersCaller = databaseCaller.getStatement().executeQuery(Queries.challengesCipherList(String.valueOf(user_id)));
            if(!ciphersCaller.next())
                return cipherChallengesList;
            else
            do {

                int challengeId = ciphersCaller.getInt(1);
                String type_cipher = ciphersCaller.getString(2);
                String cipher_message = ciphersCaller.getString(3);
                String cipher_tips = ciphersCaller.getString(4);
                cipherChallengesList.add(new CipherChallengesAttributes(challengeId,type_cipher,cipher_message,cipher_tips));
            } while (ciphersCaller.next());
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return cipherChallengesList;
    }

    /**
     * Get the hash challlenges attributes from database that a user didn't created and didn't solved
     * @param user_id the user id
     * @return the arrayList
     */
    private ArrayList<HashChallengesAttributes> hashFromDatabase(int user_id) {
        ArrayList<HashChallengesAttributes> hashChallengesList = new ArrayList<>();
        ResultSet hashCaller;
        try{
            hashCaller = databaseCaller.getStatement().executeQuery(Queries.challengesHashList(String.valueOf(user_id)));
            if(!hashCaller.next())
                return hashChallengesList;
            else
            do {
                int hash_id = hashCaller.getInt(1);
                String hash_specification = hashCaller.getString(2);
                String hash_hash = hashCaller.getString(3);
                String hash_tips = hashCaller.getString(4);
                hashChallengesList.add(new HashChallengesAttributes(hash_id,hash_specification,hash_hash,hash_tips));
            }while (hashCaller.next());
        }catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return hashChallengesList;
    }

    /**
     * receive the message and hash from the client
     * @return the deciphered message
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
            Thread.currentThread().stop();
        }
        return checkHash();
    }

    /**
     * Check if the hash is the same from the received message
     * @return
     */
    private String checkHash() {
        if(getHash(decipheredMessage,"client").equals(decipheredMessageHash)){
            return decipheredMessage;
        }
        System.out.println("Not the same hash. Disconnecting client.");
        Thread.currentThread().stop();
        return null;
    }

    /**
     * Decipher the content from client
     * @param cipherAlgorithm the algorithm
     * @param iv the iv
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     */
    private void decipherMessageAndHash(String cipherAlgorithm, IvParameterSpec iv) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        decipheredMessage = CipherDecipher.decrypt(cipheredMessage,connectionKeys.getInfo_client_server(),cipherAlgorithm,iv);
        decipheredMessageHash = CipherDecipher.decrypt(cipheredMessageHash,connectionKeys.getInfo_client_server_hash(),cipherAlgorithm,iv);
    }

    /**
     * Cipher arrayList to send to client
     * @param data the arrayList
     * @param cipherAlgorithm the algorithm
     * @param iv the iv
     * @throws NoSuchPaddingException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     */
    private void cipherMessageAndHash(ArrayList<?> data,String cipherAlgorithm, IvParameterSpec iv) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException {
        cipheredMessage = CipherDecipher.encrypt(data,connectionKeys.getInfo_server_client(),cipherAlgorithm,iv);
        cipheredMessageHash = CipherDecipher.encrypt(getHash(data),connectionKeys.getInfo_server_client_hash(),cipherAlgorithm,iv);
    }

    /**
     * Cipher the content(String) to send to client
     * @param data the String
     * @param cipherAlgorithm the algorithm
     * @param iv the iv
     * @throws NoSuchPaddingException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     */
    private void cipherMessageAndHash(String data,String cipherAlgorithm, IvParameterSpec iv) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException {
        cipheredMessage = CipherDecipher.encrypt(data,connectionKeys.getInfo_server_client(),cipherAlgorithm,iv);
        cipheredMessageHash = CipherDecipher.encrypt(getHash(data, "server"),connectionKeys.getInfo_server_client_hash(),cipherAlgorithm,iv);
    }

    /**
     * Read ciphered message from client
     * @throws IOException
     * @throws ClassNotFoundException
     */
    private void readCipheredFromClient() throws IOException, ClassNotFoundException {
        cipheredMessage = (byte[]) is.readObject();
        cipheredMessageHash = (byte[]) is.readObject();
    }

    /**
     * Send ciphered message to client
     * @param data
     * @throws IOException
     */
    private void writeCipheredToClient(byte [] data) throws IOException {
        os.writeObject(data);
        os.flush();
    }


    /**
     * Get the hash from client or server side
     * @param content the content to do the HMAC
     * @param side the side client or server
     * @return the HMAC message
     */
    private String getHash(String content, String side){
        if(content == null)
            return null;
        switch (side){
            case "server":
                return GenerateValues.doHMACMessage(content,connectionKeys.getInfo_server_client_hash());
            case "client":
                return GenerateValues.doHMACMessage(content,connectionKeys.getInfo_client_server_hash());
            default:
                return null;
        }

    }

    /**
     * Get the HMAC from an arrayList
     * @param content the arrayList
     * @return the HMAC
     */
    private String getHash(ArrayList<?> content){
        if(content == null)
            return null;
        return GenerateValues.doHMACMessage(String.valueOf(content),connectionKeys.getInfo_server_client_hash());
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
