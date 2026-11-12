package counterexamples;

import java.io.File;
import java.io.FileInputStream;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FilenameUtils;

public class CE09_SanitizedThenOverwrittenByTainted {
    public void handle(HttpServletRequest request) throws Exception {
        String path = request.getParameter("initial");
        path = FilenameUtils.getName(path);
        path = request.getParameter("override");
        FileInputStream fis = new FileInputStream(new File("/srv/files/" + path));
        fis.close();
    }
}
