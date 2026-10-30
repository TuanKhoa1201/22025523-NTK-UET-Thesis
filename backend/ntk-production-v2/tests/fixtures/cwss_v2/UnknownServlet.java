// SYNTHETIC security regression fixture; never execute repository code.
import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.nio.file.*;
class UnknownServlet extends HttpServlet {
 Connection conn;
 protected void doPost(HttpServletRequest request, HttpServletResponse response) throws javax.servlet.ServletException, IOException {
 String value = External.value(request);
 Runtime.getRuntime().exec(value); // SINK
 }
}
