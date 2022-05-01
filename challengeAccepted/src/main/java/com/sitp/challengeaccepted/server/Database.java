package com.sitp.challengeaccepted.server;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class Database {
    static final String driver = "com.mysql.jdbc.Driver";
    static final String url = "jdbc:mysql://localhost/";
    static final String user = "root";
    static final String pass = "pipas";

    public static void main (String [] args) {
        Connection connection = null;
        Statement statement = null;
        try {
            // create the database
            Class.forName("com.mysql.jdbc.Driver");
            System.out.println("Connecting to database...");
            connection = DriverManager.getConnection(url, user, pass);
            System.out.println("Creating database.");
            statement = connection.createStatement();
            String database = "CREATE DATABASE ChallengeAccepted";
            statement.executeUpdate(database);
            System.out.println("Database created successfully");
            // create the database tables
            String userTable = "CREATE TABLE user" +
                    "(user_id INTEGER NOT NULL CHECK (user_id >= 1)" +
                    "email CHAR(50) not null" +
                    "user_password CHAR(20) not null" +
                    "PRIMARY KEY (user_id))";
            statement.executeUpdate(userTable);
            System.out.println("User table created.");
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            try {
                if (statement != null) {
                    statement.close();
                }
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
            try {
                if (connection != null) {
                    connection.close();
                }
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
    }
}