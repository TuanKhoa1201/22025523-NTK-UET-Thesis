package counterexamples;

import java.io.File;
import java.io.FileInputStream;
import javax.servlet.http.HttpServletRequest;

public class CE04_UnsafeStartsWithPrefixBypass {
    public void handle(HttpServletRequest request) throws Exception {
        // "/reports-private/secret.txt".startsWith("/reports") is true without trailing "/"
        String report = request.getParameter("report");
        File target = new File("/reports", report);
        if (!target.getCanonicalPath().startsWith("/reports")) {
            return;
        }
        FileInputStream fis = new FileInputStream(target);
        fis.close();
    }
}
