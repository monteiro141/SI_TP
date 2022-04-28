module com.sitp.challengeaccepted {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.kordamp.bootstrapfx.core;

    opens com.sitp.challengeaccepted to javafx.fxml;
    exports com.sitp.challengeaccepted;
}