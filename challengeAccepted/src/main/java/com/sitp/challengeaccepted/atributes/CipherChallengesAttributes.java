package com.sitp.challengeaccepted.atributes;

import java.io.Serializable;

public class CipherChallengesAttributes implements Serializable {
    private int challenge_id;
    private String type_cipher;
    private String cipher_message;
    private String cipher_tips;

    public CipherChallengesAttributes(int challenge_id, String type_cipher, String cipher_message, String cipher_tips) {
        this.challenge_id = challenge_id;
        this.type_cipher = type_cipher;
        this.cipher_message = cipher_message;
        this.cipher_tips = cipher_tips;
    }

    public int getChallenge_id() {
        return challenge_id;
    }

    public String getType_cipher() {
        return type_cipher;
    }

    public String getCipher_message() {
        return cipher_message;
    }

    public String getCipher_tips() {
        return cipher_tips;
    }

    public void setChallenge_id(int challenge_id) {
        this.challenge_id = challenge_id;
    }

    public void setType_cipher(String type_cipher) {
        this.type_cipher = type_cipher;
    }

    public void setCipher_message(String cipher_message) {
        this.cipher_message = cipher_message;
    }

    public void setCipher_tips(String cipher_tips) {
        this.cipher_tips = cipher_tips;
    }

    @Override
    public String toString() {
        return challenge_id +
                "|" + type_cipher;

    }
}
