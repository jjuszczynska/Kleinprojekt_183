module kleinProjekt_JJ.kleinprojekt {
    requires javafx.controls;
    requires javafx.fxml;
	requires javafx.graphics;
	requires javafx.base;
	requires java.desktop;

    opens kleinProjekt_JJ.kleinprojekt to javafx.fxml;
    exports kleinProjekt_JJ.kleinprojekt;
}
