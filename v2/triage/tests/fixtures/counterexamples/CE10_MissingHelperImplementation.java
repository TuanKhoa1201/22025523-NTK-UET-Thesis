package counterexamples;

import java.io.File;
import java.io.FileInputStream;

public class CE10_MissingHelperImplementation {
    public void handle(SeparateClassRequest scr) throws Exception {
        String candidate = scr.getTheValue("id");
        String normalized = MissingSanitizerHelper.normalizePath(candidate);
        FileInputStream fis = new FileInputStream(new File("/srv/files/" + normalized));
        fis.close();
    }
}
