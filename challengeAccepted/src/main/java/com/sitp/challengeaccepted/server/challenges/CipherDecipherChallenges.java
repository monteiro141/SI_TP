package com.sitp.challengeaccepted.server.challenges;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class CipherDecipherChallenges {
    public CipherDecipherChallenges(){}

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

    private static SecretKey getPasswordWithSalt(String password, byte[] salt){
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1045733,128); //65536
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            System.out.println(Base64.getEncoder().encodeToString(factory.generateSecret(spec).getEncoded()));
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }
    public static String CreateHash(String algorithm, String message) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Unable to compute hash", ex);
        }
        if(digest!=null){
            digest.update(message.getBytes());
            //Convert o array de bytes (digest.digest()) na sua representação de magnitude de sinal
            //Convert into Hex Value
            BigInteger hash = new BigInteger(1, digest.digest());
            //16 means Hexadecimal
            return (hash.toString(16));
        }
        return null;
    }
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
}
