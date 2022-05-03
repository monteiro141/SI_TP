package com.sitp.challengeaccepted.client;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

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
}
