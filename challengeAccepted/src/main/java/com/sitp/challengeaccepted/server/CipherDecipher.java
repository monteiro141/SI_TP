package com.sitp.challengeaccepted.server;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

public class CipherDecipher {
    public CipherDecipher(){}

    /**
     * Encrypt a message with RSA public key
     * @param data the data to encrypt
     * @param publicKey the server public key
     * @return the ciphertext
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] encrypt(String data, PublicKey publicKey) throws BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data.getBytes());
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
     * Encrypt ArrayList(list of challenges to send to the client) with a secretkey
     * @param data the data
     * @param secretKey the Secret key
     * @param cipherString the algorithm to use
     * @param iv the iv
     * @return the ciphertext
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] encrypt(ArrayList<?> data, SecretKey secretKey, String cipherString, IvParameterSpec iv) throws BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        if(iv == null) {
            try {
                Cipher cipher = Cipher.getInstance(cipherString);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                return cipher.doFinal(bytesFromArrayList(data));
            } catch (IllegalBlockSizeException e) {
                System.out.println(e.getMessage());
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
        }else{
            try {
                Cipher cipher = Cipher.getInstance(cipherString);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
                return cipher.doFinal(bytesFromArrayList(data));
            } catch (IllegalBlockSizeException | InvalidKeyException | InvalidAlgorithmParameterException e) {
                System.out.println(e.getMessage());
            }
        }
        return null;
    }

    /**
     * Convert an arrayList in a byte array
     * @param data the arrayList
     * @return the byte array
     */
    public static byte[] bytesFromArrayList(ArrayList<?> data) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            ObjectOutputStream out = new ObjectOutputStream(baos);
            out.writeObject(data);
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return baos.toByteArray();
    }

    /**
     * Decrypt a message with a secret key
     * @param data the data
     * @param secretKey the Secret key to use
     * @param cipherString the algorithm of encryption to use
     * @param iv the iv
     * @return the plaintext
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
     * Derivate a password with a specified salt
     * @param salt the salt
     * @param password the password
     * @return the password salted
     */
    public static byte[] getSaltToPassword(byte[] salt, String password){
        SecretKeyFactory secretKeyFactory = null;
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt , 100000, 32);
            return secretKeyFactory.generateSecret(pbeKeySpec).getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

}
