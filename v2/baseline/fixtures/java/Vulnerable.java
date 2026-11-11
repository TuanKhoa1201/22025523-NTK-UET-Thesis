// Synthetic M1 input, deliberately vulnerable. Never deploy.
import java.io.File;
class Vulnerable {
    void run(Request req, Response resp, Statement stmt) throws Exception {
        String input = req.getParameter("input");
        String forwarded = input;
        new File(forwarded);
        Runtime.getRuntime().exec(forwarded);
        resp.getWriter().println(forwarded);
        stmt.executeQuery("SELECT * FROM users WHERE name='" + forwarded + "'");
    }
}
