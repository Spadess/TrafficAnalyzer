module app.trafficanalyzer {
    requires javafx.graphics;
    requires javafx.controls;
    requires javafx.base;
    requires javafx.fxml;
    opens logic;
    opens logic.Headers;
    opens app.trafficanalyzer to javafx.fxml;
    exports app.trafficanalyzer;
}