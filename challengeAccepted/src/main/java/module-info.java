module com.sitp.challengeaccepted {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.kordamp.bootstrapfx.core;
    requires java.sql;

    opens com.sitp.challengeaccepted to javafx.fxml;
    exports com.sitp.challengeaccepted.server;
    exports com.sitp.challengeaccepted.client;
    opens com.sitp.challengeaccepted.client to javafx.fxml;
    exports com.sitp.challengeaccepted.server.keysClasses;
    exports com.sitp.challengeaccepted.server.database;
    exports com.sitp.challengeaccepted.atributes;
    opens com.sitp.challengeaccepted.atributes to javafx.fxml;
}