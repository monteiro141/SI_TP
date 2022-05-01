package com.sitp.challengeaccepted.server.keysClasses;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class ConnectionKeys {
    private SecretKey  info_client_server;
    private SecretKey  info_server_client;
    private SecretKey  info_client_server_hash;
    private SecretKey  info_server_client_hash;

    public ConnectionKeys(){}

    public SecretKey  getInfo_client_server() {
        return info_client_server;
    }

    public void setInfo_client_server(SecretKey info_client_server) {
        this.info_client_server = info_client_server;
    }

    public SecretKey getInfo_server_client() {
        return info_server_client;
    }

    public void setInfo_server_client(SecretKey info_server_client) {
        this.info_server_client = info_server_client;
    }

    public SecretKey getInfo_client_server_hash() {
        return info_client_server_hash;
    }

    public void setInfo_client_server_hash(SecretKey info_client_server_hash) {
        this.info_client_server_hash = info_client_server_hash;
    }

    public SecretKey getInfo_server_client_hash() {
        return info_server_client_hash;
    }

    public void setInfo_server_client_hash(SecretKey info_server_client_hash) {
        this.info_server_client_hash = info_server_client_hash;
    }

    public static SecretKey generateKey(String keyString){
        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
}
