package ntk.g1.demo;

import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

/**
 * G1 Demo 3: Taint flows through an external helper absent from source snapshots -> must fail closed to UNDETERMINED.
 */
public class Demo3ExternalHelperUndetermined {

    public FileInputStream openNormalizedDocument(HttpServletRequest req) throws IOException {
        String rawDocId = req.getParameter("docId");
        String delegatedPath = ExternalPathPolicy.normalizeDocumentPath(rawDocId);
        return new FileInputStream(delegatedPath);
    }
}
