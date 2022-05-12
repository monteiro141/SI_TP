package com.sitp.challengeaccepted.server.database;

public class Queries {
    public Queries(){

    }
    public static String createDatabaseChallengeAccepted(){
        return "CREATE DATABASE IF NOT EXISTS ChallengeAccepted";
    }
    public static String createUserTable(){
        return "CREATE TABLE IF NOT EXISTS User " +
                "(user_id INTEGER NOT NULL AUTO_INCREMENT, " +
                "email CHAR(50) not null, " +
                "user_password_salted CHAR(16) not null, " +
                "PRIMARY KEY (user_id))";
    }

    public static String createCipherTable(){
        return "CREATE TABLE IF NOT EXISTS CipherChallenges " +
                "(cipher_id INTEGER NOT NULL AUTO_INCREMENT, " +
                "user_id INTEGER NOT NULL, " +
                "cipher_specification CHAR(20) not null, " +
                "cipher_hmac char(50) not null, " +
                "cipher_message char(100) not null, " +
                "iv char(16), " +
                "salt char(16) not null, " +
                "cipher_tips char(50), " +
                "PRIMARY KEY (cipher_id), " +
                "CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES User(user_id))";
    }

    public static String createHashTable(){
        return "CREATE TABLE IF NOT EXISTS HashChallenges " +
                "(hash_id INTEGER NOT NULL AUTO_INCREMENT, " +
                "user_id INTEGER NOT NULL, " +
                "hash_specification CHAR(20) not null, " +
                "hash_hash CHAR(50) not null, " +
                "hash_tips char(50), " +
                "PRIMARY KEY (hash_id), " +
                "CONSTRAINT fk_user_id_hash FOREIGN KEY (user_id) REFERENCES User(user_id))";
    }
}
