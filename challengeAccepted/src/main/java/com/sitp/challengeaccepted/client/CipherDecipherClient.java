package com.sitp.challengeaccepted.client;

import com.sitp.challengeaccepted.atributes.CipherChallengesAttributes;
import com.sitp.challengeaccepted.atributes.HashChallengesAttributes;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;

public class CipherDecipherClient {
    public CipherDecipherClient(){

    }
    /**
     * Encrypt a message with RSA public key
     * @param data_key the data to encrypt
     * @param key the server public key
     * @return the ciphertext
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] encrypt(String data_key, PublicKey key) throws BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data_key.getBytes());
        } catch (IllegalBlockSizeException e) {
            System.out.println(e.getMessage());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypt a ciphertext with RSA private key
     * @param data the data
     * @param privateKey the server private key
     * @return the plaintext
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }

    /**
     * Encrypt a message with a secret key
     * @param data the data
     * @param secretKey the Secret key to use
     * @param cipherString the algorithm of encryption to use
     * @param iv the iv
     * @return the  ciphertext
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] encrypt(String data, SecretKey secretKey, String cipherString, IvParameterSpec iv) throws BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        if(iv == null) {
            try {
                Cipher cipher = Cipher.getInstance(cipherString);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                return cipher.doFinal(data.getBytes());
            } catch (IllegalBlockSizeException e) {
                System.out.println(e.getMessage());
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
        }else{
            try {
                Cipher cipher = Cipher.getInstance(cipherString);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
                return cipher.doFinal(data.getBytes());
            } catch (IllegalBlockSizeException | InvalidKeyException | InvalidAlgorithmParameterException e) {
                System.out.println(e.getMessage());
            }
        }
        return null;
    }

    /**
     * Decrypts a message with a secret key
     * @param data the data
     * @param secretKey the Secret key to use
     * @param cipherString the algorithm of encryption to use
     * @param iv the iv
     * @return the  ciphertext
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String decrypt(byte[] data, SecretKey secretKey, String cipherString, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if(iv == null){
            Cipher cipher = Cipher.getInstance(cipherString);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(data));
        }
        else
        {
            Cipher cipher = Cipher.getInstance(cipherString);
            try {
                cipher.init(Cipher.DECRYPT_MODE, secretKey,iv);
            } catch (InvalidAlgorithmParameterException e) {
                System.out.println(e.getMessage());
            }
            return new String(cipher.doFinal(data));
        }
    }

    /**
     * Decrypts the lists of cipher challenges
     * @param data the data
     * @param secretKey the Secret key to use
     * @param cipherString the algorithm of encryption to use
     * @param iv the iv
     * @return the arraylist of cipher challenges
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static ArrayList<CipherChallengesAttributes> CipherdecryptLists(byte[] data, SecretKey secretKey, String cipherString, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        ArrayList<CipherChallengesAttributes> ch = new ArrayList<>();
        Cipher cipher = Cipher.getInstance(cipherString);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decipher = cipher.doFinal(data);
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(decipher);
            ObjectInputStream ois = new ObjectInputStream(bis);
            try {
                ch = (ArrayList<CipherChallengesAttributes>) ois.readObject();
                ois.close();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return ch;
    }

    /**
     * Decrypts the lists of hash challenges
     * @param data the data
     * @param secretKey the Secret key to use
     * @param cipherString the algorithm of encryption to use
     * @param iv the iv
     * @return the arraylist of hash challenges
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static ArrayList<HashChallengesAttributes> HashdecryptLists(byte[] data, SecretKey secretKey, String cipherString, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        ArrayList<HashChallengesAttributes> ch = new ArrayList<>();
        Cipher cipher = Cipher.getInstance(cipherString);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decipher = cipher.doFinal(data);
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(decipher);
            ObjectInputStream ois = new ObjectInputStream(bis);
            try {
                ch = (ArrayList<HashChallengesAttributes>) ois.readObject();
                ois.close();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return ch;
    }

    /**
     * Function to create Hmac message
     * @param message message to create hmac with
     * @param key secret key to be used when creating hmac
     * @return hmac
     */
    public static String doHMACMessage(String message, SecretKey key){
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            BigInteger hash = new BigInteger(1, mac.doFinal(message.getBytes()));
            return (hash.toString(16));
        } catch (NoSuchAlgorithmException | InvalidKeyException e){
            System.out.println(e.getMessage());
        }
        return null;
    }
}
