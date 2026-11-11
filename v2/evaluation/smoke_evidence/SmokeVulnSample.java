package vn.edu.uet.ntk.v2.smoke;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FilenameUtils;

/**
 * Isolated Java smoke-test fixture for NTK Thesis V2 (M0/M1 OpenGrep verification).
 * Contains:
 * 1. True Positive CWE-89 (SQL Injection with taint source -> intermediate var -> sink)
 * 2. True Positive CWE-22 (Path Traversal with taint source -> intermediate var -> sink)
 * 3. Safe Negative Control CWE-89 (Parameterized PreparedStatement)
 * 4. Safe Negative Control CWE-22 (Sanitized via FilenameUtils.getName)
 */
public class SmokeVulnSample {

    public ResultSet unsafeSqlLookup(HttpServletRequest request, Connection conn) throws SQLException {
        String userInput = request.getParameter("username");
        String query = "SELECT id, role FROM users WHERE username = '" + userInput + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query);
    }

    public FileInputStream unsafeFileRead(HttpServletRequest request) throws IOException {
        String rawReportName = request.getParameter("report");
        File targetFile = new File("/var/app/reports/" + rawReportName);
        return new FileInputStream(targetFile);
    }

    public ResultSet safeSqlLookup(HttpServletRequest request, Connection conn) throws SQLException {
        String userInput = request.getParameter("username");
        PreparedStatement ps = conn.prepareStatement("SELECT id, role FROM users WHERE username = ?");
        ps.setString(1, userInput);
        return ps.executeQuery();
    }

    public FileInputStream safeFileRead(HttpServletRequest request) throws IOException {
        String rawReportName = request.getParameter("report");
        String cleanName = FilenameUtils.getName(rawReportName);
        File targetFile = new File("/var/app/reports/" + cleanName);
        return new FileInputStream(targetFile);
    }
}
