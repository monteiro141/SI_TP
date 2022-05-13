package com.sitp.challengeaccepted.server.challenges;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class GenerateValues {
    public GenerateValues(){}

    public static byte[] getSalt(){
        byte[] salt = new byte[16];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(salt);
        return salt;
    }

    public static byte[] getIvVector() {
        SecureRandom random = null;
        try {
            random = SecureRandom.getInstanceStrong();
            byte[] iv = new byte[Cipher.getInstance("AES").getBlockSize()];
            random.nextBytes(iv);
            return iv;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.out.println(e.getMessage());
        }
        return null;
    }

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
