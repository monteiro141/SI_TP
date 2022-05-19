package com.sitp.challengeaccepted.server.database;

import com.sitp.challengeaccepted.server.User;

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
                "user_password_salted CHAR(32) not null, " +
                "PRIMARY KEY (user_id))";
    }

    public static String createCipherTable(){
        return "CREATE TABLE IF NOT EXISTS CipherChallenges " +
                "(cipher_id INTEGER NOT NULL AUTO_INCREMENT, " +
                "user_id INTEGER NOT NULL, " +
                "cipher_specification CHAR(20) not null, " +
                "cipher_hmac char(64) not null, " +
                "cipher_message char(255) not null, " +
                "iv varbinary(16), " +
                "salt varbinary(16), " +
                "cipher_tips char(128), " +
                "signature text not null, " +
                "PRIMARY KEY (cipher_id), " +
                "CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES User(user_id))";
    }

    public static String createHashTable(){
        return "CREATE TABLE IF NOT EXISTS HashChallenges " +
                "(hash_id INTEGER NOT NULL AUTO_INCREMENT, " +
                "user_id INTEGER NOT NULL, " +
                "hash_specification CHAR(20) not null, " +
                "hash_hash CHAR(128) not null, " +
                "hash_tips char(128), " +
                "PRIMARY KEY (hash_id), " +
                "CONSTRAINT fk_user_id_hash FOREIGN KEY (user_id) REFERENCES User(user_id))";
    }

    public static String createSolvedTable () {
        return "CREATE TABLE IF NOT EXISTS SolvedChallenges " +
                "(user_id INTEGER NOT NULL, " +
                "cipher_id INTEGER, " +
                "hash_id INTEGER, " +
                "CONSTRAINT fk_user_id_solved FOREIGN KEY (user_id) REFERENCES User(user_id), " +
                "CONSTRAINT fk_cipher_id FOREIGN KEY (cipher_id) REFERENCES CipherChallenges(cipher_id), " +
                "CONSTRAINT fk_hash_id FOREIGN KEY (hash_id) REFERENCES HashChallenges(hash_id))";
    }

    public static String loginUser(String email, String salted_password){
        return "SELECT user_id, email "+
                "FROM User" +
                " WHERE email = '" + email +"'" +
                " AND user_password_salted = '"+ salted_password+"'";
    }
    public static String loginUser(String email){
        return "SELECT user_id, email "+
                "FROM User" +
                " WHERE email = '" + email+"'";
    }
    public static String registerUser(String email, String salted_password){
        return "INSERT INTO User (email, user_password_salted) " +
                "VALUES ('" + email + "', '" + salted_password + "');";
    }
    public static String checkHMAC (String hmac, String cipher_specification) {
        return "SELECT cipher_hmac " +
                "FROM CipherChallenges " +
                "WHERE cipher_hmac = '" + hmac + "' AND "+
                " cipher_specification = '"+cipher_specification+"'";
    }

    public static String checkHash (String hash) {
        return "SELECT hash_hash " +
                "FROM HashChallenges " +
                "WHERE hash_hash = '" + hash + "'";
    }

    public static String createCipherChallenge () {
        String sql = "INSERT INTO CipherChallenges (user_id, cipher_specification, cipher_hmac, cipher_message, iv, salt, cipher_tips, signature) " +
               "VALUES(?,?,?,?,?,?,?,?) ";
        return sql;
    }

    public static String createHashChallenge (User user, String challengeSpecification, String hash, String tips) {
        return "INSERT INTO HashChallenges (user_id, hash_specification, hash_hash, hash_tips) " +
                "VALUES (" + user.getUser_id() + ", '" + challengeSpecification + "', '" + hash + "', '" + tips + "');";
    }

    public static String resolvedCipher (String user_id, String cipher_id) {
        return "INSERT INTO SolvedChallenges (user_id, cipher_id) " +
                "VALUES ('" + user_id + "', '" + cipher_id + "');";
    }

    public static String challengesCipherList(String user_id){
        return "SELECT cipher_id, cipher_specification, cipher_message, cipher_tips "+
                "FROM CipherChallenges c "+
                "WHERE c.user_id != '"+user_id+"' AND NOT EXISTS (" +
                "SELECT user_id, cipher_id " +
                "FROM SolvedChallenges s " +
                "WHERE c.cipher_id = s.cipher_id AND '"+ user_id + "' = s.user_id)";
        /* PROBS WRONG (99.9 certainty)
        return "SELECT cipher_id, cipher_specification, cipher_message, cipher_tips "+
                "FROM CipherChallenges c, SolvedChallenges s "+
                "WHERE c.user_id != '"+user_id+"' AND c.user_id = s.user_id AND c.cipher_id != s.cipher_id";*/
    }

    public static String challengesHashList(String user_id){
        return "SELECT hash_id, hash_specification, hash_hash, hash_tips "+
                "FROM HashChallenges "+
                "WHERE user_id != '"+user_id+"'";
    }

    public static String getCipherChallengeData(String cipher_id) {
        return "SELECT cipher_specification, cipher_hmac, cipher_message, iv, salt, signature " +
                "FROM CipherChallenges " +
                "WHERE cipher_id = '" + cipher_id + "'";
    }

    public static String getHashChallengeData (String hash_id) {
        return "SELECT hash_specification, hash_hash " +
                "FROM HashChallenges " +
                "WHERE hash_id = '" + hash_id + "'";
    }
}