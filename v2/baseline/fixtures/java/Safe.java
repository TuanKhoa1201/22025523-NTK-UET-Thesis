// Synthetic negative control for these four source/sink demonstration rules.
import java.io.File;
class Safe {
    void run(Response resp, Statement stmt) throws Exception {
        new File("fixed.txt");
        Runtime.getRuntime().exec("fixed-command");
        resp.getWriter().println("fixed text");
        stmt.executeQuery("SELECT 1");
    }
}
