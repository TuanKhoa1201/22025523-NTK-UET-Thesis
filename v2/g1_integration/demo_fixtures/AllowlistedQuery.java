package ntk.g1.demo;

import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

/**
 * PROPOSED G1 R03 False-Positive replacement candidate (reused from v2/triage/demo_queue.py:SAFE_JAVA).
 *
 * Untrusted SQL input from HttpServletRequest.getParameter("q") triggers the OpenGrep CWE-89 rule,
 * while an in-memory exact literal allowlist (!"SELECT 1".equals(query)) throws on every other value
 * before stmt.executeQuery(query). Unlike Demo2's filesystem path check, this guard has no symlink
 * or TOCTOU filesystem race dependency.
 */
public class AllowlistedQuery {

    public void run(HttpServletRequest req, Statement stmt) throws SQLException {
        String query = req.getParameter("q");
        if (!"SELECT 1".equals(query)) {
            throw new IllegalArgumentException("Only SELECT 1 is allowed");
        }
        stmt.executeQuery(query);
    }
}
