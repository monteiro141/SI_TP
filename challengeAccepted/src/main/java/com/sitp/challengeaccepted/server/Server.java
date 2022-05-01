package com.sitp.challengeaccepted.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
    private ServerSocket SS;
    private Socket S;
    private ConnectionThread C;
    private static int port = 1099;

    public Server() {
        createServerSocket();
        acceptFromServerSocket();
    }

    public static void main(String[] args) {
        Server s = new Server();
    }

    /**
     * Starts up a new ServerSocket on @port
     */
    private void createServerSocket() {
        try {
            SS = new ServerSocket(port);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     * Waits a connection from a client
     */
    private void acceptFromServerSocket() {
        while (true) {
            try {
                S = SS.accept();
                C = new ConnectionThread(S);
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        }
    }


}
