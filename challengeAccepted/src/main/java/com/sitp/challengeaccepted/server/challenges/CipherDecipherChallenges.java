package com.sitp.challengeaccepted.server.challenges;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Locale;

public class CipherDecipherChallenges {
    public CipherDecipherChallenges(){}

    /**
     * Encrypt a plaintext with a specified key for cipher mode. The key is derivated from a password.
     * @param type the type of encryption: AES-128-ECB; AES-128-CBC; AES-128-CTR; Vigenere
     * @param message the plaintext to encrypt
     * @param password the password
     * @param salt the salt used to derivate the password
     * @param ivVector the iv vector for some types of encryption: AES-128-CBC; AES-128-CTR
     * @return the ciphertext
     */
    public static String encryptCipher(String type, String message, String password, byte[] salt, IvParameterSpec ivVector){
        try {
            switch(type){
                case "AES-128-ECB" -> {
                    return encrypt("AES/ECB/PKCS5Padding", message, getPasswordWithSalt(password, salt), null);
                }
                case "AES-128-CBC" -> {
                    return encrypt("AES/CBC/PKCS5Padding", message, getPasswordWithSalt(password, salt), ivVector);
                }
                case "AES-128-CTR" -> {
                    return encrypt("AES/CTR/NoPadding", message, getPasswordWithSalt(password, salt), ivVector);
                }
                case "VIGENERE" -> {
                    return encryptVigenere(message, generateVigenereKey(message, password));
                }
            }
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypt a ciphertext with a specified key for cipher mode. The key is derivated from a password.
     * @param type the type of decryption: AES-128-ECB; AES-128-CBC; AES-128-CTR; Vigenere
     * @param message the ciphertext to decrypt
     * @param password the password
     * @param salt the salt used to derivate the password
     * @param ivVector the iv vector for some types of decryption: AES-128-CBC; AES-128-CTR
     * @return the plaintext
     */
    public static String decryptCipher (String type, String message, String password, byte[] salt, IvParameterSpec ivVector) {
        try {
            switch(type){
                case "AES-128-ECB" -> {
                    return decrypt("AES/ECB/PKCS5Padding", message, getPasswordWithSalt(password, salt), null);
                }
                case "AES-128-CBC" -> {
                    return decrypt("AES/CBC/PKCS5Padding", message, getPasswordWithSalt(password, salt), ivVector);
                }
                case "AES-128-CTR" -> {
                    return decrypt("AES/CTR/NoPadding", message, getPasswordWithSalt(password, salt), ivVector);
                }
                case "VIGENERE" -> {
                    return decryptVigenere(message, generateVigenereKey(message, password));
                }
            }
        } catch (BadPaddingException ex){
            return null;
        }
        catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Encrypt a plaintext with the specified type
     * @param algorithm the algorithm of encryption
     * @param input the plaintext to encrypt
     * @param key the Secret key to use
     * @param iv the iv vector
     * @return the ciphertext
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String encrypt(String algorithm, String input, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        if(algorithm.equals("AES/ECB/PKCS5Padding")){
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }else{
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        }
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }

    /**
     * Decrypt a ciphertext with a specified type
     * @param algorithm the algorithm of decryption
     * @param cipherText the ciphertext to decrypt
     * @param key the Secret key to use
     * @param iv the iv vector
     * @return the plaintext
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String decrypt(String algorithm, String cipherText, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        if(algorithm.equals("AES/ECB/NoPadding")){
            cipher.init(Cipher.DECRYPT_MODE, key);
        }else{
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
        }
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

    /**
     * Derivate a Secret Key from a password
     * @param password the password inserted by the user
     * @param salt the salt random generated
     * @return the secret key to use in encryption or decryption
     */
    public static SecretKey getPasswordWithSalt(String password, byte[] salt){
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 2500000,128); //65536
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            System.out.println(Base64.getEncoder().encodeToString(factory.generateSecret(spec).getEncoded()));
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Create a Hash of a specified message
     * @param algorithm the Hash algorithm to use: MD5; SHA256; SHA512
     * @param message the message
     * @return the hash
     */
    public static String CreateHash(String algorithm, String message) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Unable to compute hash", ex);
        }
        if(digest!=null){
            digest.update(message.getBytes());
            //Convert into Hex Value
            BigInteger hash = new BigInteger(1, digest.digest());
            //16 means Hexadecimal
            return (hash.toString(16));
        }
        return null;
    }

    /**
     * Encrypt a message using vigenere
     * @param message the plaintext to encrypt
     * @param password the password
     * @return the ciphertext
     */
    public static String encryptVigenere(String message, String password){
        StringBuilder ciphertext = new StringBuilder();
        for (int i =0 ;i <message.length();i++) {
            if (message.charAt(i) != ' '){
                int newCharacter = ((message.charAt(i) - 'A') + (password.charAt(i)- 'A')) % 26;
                ciphertext.append((char)('A' + newCharacter));
            }else{
                ciphertext.append(message.charAt(i));
            }
        }
        return ciphertext.toString();
    }

    /**
     * Decrypt a message using vigenere
     * @param message the ciphertext to decrypt
     * @param password the password to use
     * @return the plaintext
     */
    public static String decryptVigenere(String message, String password){
        StringBuilder ciphertext = new StringBuilder();
        for (int i =0 ;i <message.length();i++) {
            if (message.charAt(i) != ' '){
                int newCharacter = ((message.charAt(i) - 'A') - (password.charAt(i)- 'A') + 26) % 26;
                ciphertext.append((char)('A' + newCharacter));
            }else{
                ciphertext.append(message.charAt(i));
            }
        }
        return ciphertext.toString();
    }

    /**
     * Generate the vigenere key to use in encryption or decryption
     * @param message the message(can be the ciphertext or plaintext)
     * @param password the password
     * @return return the key with the lenght needed to encrypt or decrypt
     */
    private static String generateVigenereKey(String message, String password){
        if(message.length()==password.length()){
            return password;
        }
        StringBuilder key= new StringBuilder();
        int passSize=password.length();
        int positionPassword=0;
        for(int i=0 ; i<message.length(); i++){
            if(passSize==positionPassword){
                positionPassword=0;
            }
            if(message.charAt(i) == ' '){
                key.append(" ");
            }else{
                key.append(password.charAt(positionPassword));
                positionPassword++;
            }
        }
        return key.toString();
    }

    /**
     * Encrypt a plaintext with caesar cipher with a offset
     * @param message the message to encrypt
     * @param offset the offset to use
     * @return the ciphertext
     */
    public static String encryptCesar(String message, int offset){
        StringBuilder ciphertext = new StringBuilder();
        for(char character : message.toCharArray()){
            if(character != ' '){
                int newCharacter = ((character - 'A') + offset) % 26;
                ciphertext.append((char)('A' + newCharacter));
            }else{
                ciphertext.append(character);
            }
        }
        return ciphertext.toString();
    }

    /**
     * Decrypt a ciphertext with caesar cipher with a offset
     * @param message the message to decrypt
     * @param offset the offset to use
     * @return the plaintext
     */
    public static String decryptCesar(String message, int offset){
        StringBuilder ciphertext = new StringBuilder();
        for(char character : message.toCharArray()){
            if(character != ' '){
                int newCharacter = ((character - 'A') - offset) % 26;
                if(newCharacter < 0)
                    newCharacter = newCharacter + 26;
                ciphertext.append((char)('A' + newCharacter));
            }else{
                ciphertext.append(character);
            }
        }
        return ciphertext.toString();
    }

    /**
     * Encrypt a plaintext using ElGamal
     * @param message the message
     * @param yString the y that the user has entered
     * @return the ciphertext
     */
    public static ArrayList<String> encryptElGamal(String message, String yString) {
        ArrayList<String> valuesToReturn= new ArrayList<>();
        String ciphertext=null;
        int P = 31;
        int G = 11;
        //to do Alice side
        int xGenerated = new SecureRandom().nextInt(2, P-1);

        BigInteger p = new BigInteger(String.valueOf(P));
        BigInteger g = new BigInteger(String.valueOf(G));
        BigInteger x = new BigInteger(String.valueOf(xGenerated));
        BigInteger X =g.pow(xGenerated).remainder(p);

        //Bob side
        int y= Integer.parseInt(yString);
        BigInteger Y = g.pow(y).remainder(p);

        BigInteger key = X.pow(y).remainder(p);
        String aesKeyHash = CreateHash("MD5", String.valueOf(X) + key);

        SecretKey keytoencrypt = convertStringToSecretKeyto(aesKeyHash);
        try {
            ciphertext = encrypt("AES/ECB/PKCS5Padding", message, keytoencrypt, null);
        }catch(BadPaddingException ex){
            return null;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        valuesToReturn.add(ciphertext);
        valuesToReturn.add(String.valueOf(Y));
        valuesToReturn.add(String.valueOf(X));
        return valuesToReturn;
    }

    /**
     * Decrypt a ciphertext using ElGamal
     * @param message the message
     * @param xString the x that the user has entered
     * @param YString the Y
     * @param X the X
     * @return the plaintext
     */
    public static String decryptElGamal(String message, String xString, String YString, String X) {
        System.out.println(X);
        String plaintext=null;
        int P = 31;
        int G = 11;

        BigInteger p = new BigInteger(String.valueOf(P));
        BigInteger Y = new BigInteger(YString);
        int x = Integer.parseInt(xString);


        BigInteger key = Y.pow(x).remainder(p);

        String aesKeyHash = CreateHash("MD5", String.valueOf(X) + key);

        SecretKey keytoencrypt = convertStringToSecretKeyto(aesKeyHash);
        try {
            plaintext = decrypt("AES/ECB/PKCS5Padding", message, keytoencrypt, null);
        }catch(BadPaddingException ex){
            return null;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return plaintext;
    }


    /**
     * Convert a String to a Secretkey
     * @param encodedKey the encodedKey
     * @return the Secretkey
     */
    private static SecretKey convertStringToSecretKeyto(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return originalKey;
    }
}
