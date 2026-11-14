package counterexamples;

import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class CE03_OneBranchOnlySafeAssignment {
    public void handle(HttpServletRequest request, Statement stmt) throws Exception {
        String user = request.getParameter("user");
        if ("guest".equals(request.getHeader("X-Mode"))) {
            user = "guest_default";
        }
        stmt.executeQuery("SELECT * FROM accounts WHERE username='" + user + "'");
    }
}
