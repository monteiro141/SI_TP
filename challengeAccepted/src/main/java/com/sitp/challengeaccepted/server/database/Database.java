package com.sitp.challengeaccepted.server.database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class Database {
    //static final String driver = "com.mysql.jdbc.Driver";
    static final String url = "jdbc:mysql://localhost:3306/challengeaccepted";
    static final String user = "root";
    static final String pass = "root";
    private static Connection connection = null;
    private static Statement statement = null;

    public static void main (String [] args) {

        System.out.println("Loading driver...");

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            System.out.println("Driver loaded!");
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("Cannot find the driver in the classpath!", e);
        }

        try {
            // create the database
            //Class.forName("com.mysql.jdbc.Driver");
            System.out.println("Connecting to database...");
            connection = DriverManager.getConnection(url, user, pass);
            System.out.println("Creating database.");
            statement = connection.createStatement();
            String database = Queries.createDatabaseChallengeAccepted();
            statement.executeUpdate(database);
            System.out.println("Database created successfully");
        }catch (SQLException sqlException) {
            if (sqlException.getErrorCode() == 1007) {
                // Database already exists error
                System.out.println("Database already exists.");
            } else {
                // Some other problems, e.g. Server down, no permission, etc
                sqlException.printStackTrace();
            }
        }
        // create the database tables
        try {
            String userTable = Queries.createUserTable();
            statement.executeUpdate(userTable);
            System.out.println("User table created.");
        } catch (SQLException e) {
            if (e.getErrorCode() == 1007) {
                // Database already exists error
                System.out.println("User table already exists.");
            } else {
                // Some other problems, e.g. Server down, no permission, etc
                e.printStackTrace();
            }
        }
        try {
            String cipherTable = Queries.createCipherTable();
            statement.executeUpdate(cipherTable);
            System.out.println("Cipher table created.");
        } catch (SQLException e) {
            if (e.getErrorCode() == 1007) {
                // Database already exists error
                System.out.println("Cipher table already exists.");
            } else {
                // Some other problems, e.g. Server down, no permission, etc
                e.printStackTrace();
            }
        }
        try {
            String hashTable = Queries.createHashTable();
            statement.executeUpdate(hashTable);
            System.out.println("Hash table created.");
        } catch (SQLException e) {
            if (e.getErrorCode() == 1007) {
                // Database already exists error
                System.out.println("Hash table already exists.");
            } else {
                // Some other problems, e.g. Server down, no permission, etc
                e.printStackTrace();
            }
        } finally {
            try {
                if (statement != null) {
                    statement.close();
                }
            } catch (Exception e) {
                System.out.println("Error closing the statement.");
            }
            try {
                if (connection != null) {
                    connection.close();
                }
            } catch (Exception e) {
                System.out.println("Error closing the connector.");
            }
        }
    }

    public static void ConnectToDatabase(){
        try {
            connection = DriverManager.getConnection(url, user, pass);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        System.out.println("Creating database.");
        try {
            statement = connection.createStatement();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

}