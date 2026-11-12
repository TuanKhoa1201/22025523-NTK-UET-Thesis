package ntk.g1.demo;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

/**
 * G1 Demo 1: True-positive Java CWE-89 and CWE-22 taint flows with explicit source, propagation, and sink.
 */
public class Demo1TruePositive {

    public ResultSet lookupUserByRole(HttpServletRequest req, Statement stmt) throws SQLException {
        String role = req.getParameter("role");
        String normalizedRole = role.trim();
        String sql = "SELECT id, username FROM users WHERE role = '" + normalizedRole + "'";
        return stmt.executeQuery(sql);
    }

    public FileInputStream downloadInvoiceFile(HttpServletRequest req) throws IOException {
        String invoiceName = req.getParameter("file");
        String targetPath = "/srv/invoices/" + invoiceName;
        return new FileInputStream(targetPath);
    }
}
