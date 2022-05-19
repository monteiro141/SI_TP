package com.sitp.challengeaccepted.server.database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class Database {
    //static final String driver = "com.mysql.jdbc.Driver";
    static final String url = "jdbc:mysql://localhost:3306/";
    static final String db_url = "challengeaccepted";
    static final String user = "SI_USER";
    static final String pass = "root";
    private Connection connection;
    private Statement statement;

    public Database(){
    }

    public Connection getConnection() {
        return connection;
    }

    public void setConnection(Connection connection) {
        this.connection = connection;
    }

    public Statement getStatement() {
        return statement;
    }

    public void setStatement(Statement statement) {
        this.statement = statement;
    }

    public static void main (String [] args) {
        Connection connection = null;
        Statement statement = null;
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
            connection = DriverManager.getConnection(url+db_url, user, pass);
            statement = connection.createStatement();
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
        }
        try {
            String solvedTable = Queries.createSolvedTable();
            statement.executeUpdate(solvedTable);
            System.out.println("Solved challenges table created.");
        } catch (SQLException e) {
            if (e.getErrorCode() == 1007) {
                // Database already exists error
                System.out.println("Solved challenges table already exists.");
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

    public boolean ConnectToDatabase(){
        try {
            connection = DriverManager.getConnection(url+db_url, user, pass);
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
        try {
            statement = connection.createStatement();
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

}