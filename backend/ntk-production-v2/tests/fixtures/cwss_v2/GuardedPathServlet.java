// SYNTHETIC security regression fixture; never execute repository code.
import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.nio.file.*;
class GuardedPathServlet extends HttpServlet {
 Connection conn;
 protected void doPost(HttpServletRequest request, HttpServletResponse response) throws javax.servlet.ServletException, IOException {
 Path base = Paths.get("/srv/data").toAbsolutePath().normalize();
 Path value = Paths.get(request.getParameter("path")).normalize();
 if (!value.startsWith(base)) { throw new SecurityException(); }
 Files.readAllBytes(value); // SINK
 }
}
