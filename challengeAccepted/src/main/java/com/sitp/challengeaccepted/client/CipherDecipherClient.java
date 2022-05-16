package com.sitp.challengeaccepted.client;

import com.sitp.challengeaccepted.atributes.CipherChallengesAttributes;
import com.sitp.challengeaccepted.atributes.HashChallengesAttributes;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.*;
import java.util.ArrayList;

public class CipherDecipherClient {
    public CipherDecipherClient(){}
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
    public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }

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
}
