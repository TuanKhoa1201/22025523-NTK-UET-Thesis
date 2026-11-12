package counterexamples;

import java.io.File;
import java.io.FileInputStream;
import javax.servlet.http.HttpServletRequest;

public class CE05_CanonicalPathOnDifferentObject {
    public void handle(HttpServletRequest request) throws Exception {
        String input = request.getParameter("doc");
        File safeFile = new File("/srv/docs/index.txt");
        File userFile = new File("/srv/docs", input);
        if (!safeFile.getCanonicalPath().startsWith("/srv/docs/")) {
            return;
        }
        FileInputStream fis = new FileInputStream(userFile);
        fis.close();
    }
}
