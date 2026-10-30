// SYNTHETIC security regression fixture; never execute repository code.
import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.nio.file.*;
class HelperServlet extends HttpServlet {
 Connection conn;
 protected void doPost(HttpServletRequest request, HttpServletResponse response) throws javax.servlet.ServletException, IOException {
 String value = forward(request);
 Runtime.getRuntime().exec(value); // SINK
 }
 String forward(HttpServletRequest input) { return input.getParameter("v"); }
}
