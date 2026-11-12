package counterexamples;

import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class CE01_UnrelatedSanitizerSQLi {
    public void handle(HttpServletRequest request, Statement stmt) throws Exception {
        String name = request.getParameter("name");
        int safeNumber = Integer.parseInt("7");
        stmt.executeQuery("SELECT * FROM users WHERE name='" + name + "' AND role=" + safeNumber);
    }
}
