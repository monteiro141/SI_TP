module com.sitp.challengeaccepted {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.kordamp.bootstrapfx.core;
    requires java.sql;

    opens com.sitp.challengeaccepted to javafx.fxml;
    exports com.sitp.challengeaccepted.server;
    exports com.sitp.challengeaccepted.client;
    exports com.sitp.challengeaccepted.server.keys;
    opens com.sitp.challengeaccepted.client to javafx.fxml;
    exports com.sitp.challengeaccepted.server.keysClasses;
}