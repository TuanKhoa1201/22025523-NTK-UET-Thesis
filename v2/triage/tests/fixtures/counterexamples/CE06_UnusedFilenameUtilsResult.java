package counterexamples;

import java.io.File;
import java.io.FileInputStream;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FilenameUtils;

public class CE06_UnusedFilenameUtilsResult {
    public void handle(HttpServletRequest request) throws Exception {
        String rawPath = request.getParameter("file");
        String cleanName = FilenameUtils.getName(rawPath);
        FileInputStream fis = new FileInputStream(new File("/srv/uploads/" + rawPath));
        fis.close();
    }
}
