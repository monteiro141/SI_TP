package com.sitp.challengeaccepted.server;

import com.sitp.challengeaccepted.server.challenges.CipherChallengesAttributes;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

public class CipherDecipher {
    public CipherDecipher(){}
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
