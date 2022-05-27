package com.sitp.challengeaccepted.server.challenges;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class GenerateValues {
    public GenerateValues(){}

    /**
     * Generate a random salt with 16 bytes
     * @return the salt
     */
    public static byte[] getSalt(){
        byte[] salt = new byte[16];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(salt);
        return salt;
    }

    /**
     * Generate a random Iv
     * @return the iv
     */
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

    /**
     * Create a HMAC with a specify message and Secret Key
     * @param message the message
     * @param key the Secret Key
     * @return the HMAC
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

    /**
     * Do the signature of a message
     * @param message the message
     * @param key the private key to use
     * @return the signature
     */
    public static String signMessage (String message, PrivateKey key) {
        try {
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(key);
            sign.update(message.getBytes());
            byte [] signature = sign.sign();
            return Base64.getEncoder().encodeToString(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Verify if a signature is valid
     * @param message the message
     * @param signature the signature
     * @param key the public key
     * @return true if it is valid or false if not
     */
    public static boolean verifySignature (String message, String signature, PublicKey key) {
        try {
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initVerify(key);
            sign.update(message.getBytes());
            byte [] signed = Base64.getDecoder().decode(signature);
            return sign.verify(signed);
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }


}
