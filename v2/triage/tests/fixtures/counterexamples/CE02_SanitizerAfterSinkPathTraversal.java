package counterexamples;

import java.io.File;
import java.io.FileInputStream;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FilenameUtils;

public class CE02_SanitizerAfterSinkPathTraversal {
    public void handle(HttpServletRequest request) throws Exception {
        String fileName = request.getParameter("file");
        FileInputStream fis = new FileInputStream(new File("/var/data/" + fileName));
        String cleanedTooLate = FilenameUtils.getName(fileName);
        fis.close();
    }
}
