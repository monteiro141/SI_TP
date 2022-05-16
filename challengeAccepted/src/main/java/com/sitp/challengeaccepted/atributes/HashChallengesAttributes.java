package com.sitp.challengeaccepted.atributes;

import java.io.Serializable;

public class HashChallengesAttributes implements Serializable {
    private int hash_id;
    private String hash_specification;
    private String hash_hash;
    private String hash_tips;

    public HashChallengesAttributes(int hash_id, String hash_specification, String hash_hash, String hash_tips) {
        this.hash_id = hash_id;
        this.hash_specification = hash_specification;
        this.hash_hash = hash_hash;
        this.hash_tips = hash_tips;
    }

    public int getHash_id() {
        return hash_id;
    }

    public void setHash_id(int hash_id) {
        this.hash_id = hash_id;
    }

    public String getHash_specification() {
        return hash_specification;
    }

    public void setHash_specification(String hash_specification) {
        this.hash_specification = hash_specification;
    }

    public String getHash_hash() {
        return hash_hash;
    }

    public void setHash_hash(String hash_hash) {
        this.hash_hash = hash_hash;
    }

    public String getHash_tips() {
        return hash_tips;
    }

    public void setHash_tips(String hash_tips) {
        this.hash_tips = hash_tips;
    }

    @Override
    public String toString() {
        return "HashChallengesAttributes{" +
                "hash_id=" + hash_id +
                ", hash_specification='" + hash_specification + '\'' +
                ", hash_hash='" + hash_hash + '\'' +
                ", hash_tips='" + hash_tips + '\'' +
                '}';
    }
}
