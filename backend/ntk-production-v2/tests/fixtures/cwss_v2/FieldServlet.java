// SYNTHETIC security regression fixture; never execute repository code.
import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.nio.file.*;
class FieldServlet extends HttpServlet {
 Connection conn;
 protected void doPost(HttpServletRequest request, HttpServletResponse response) throws javax.servlet.ServletException, IOException {
 cached = request;
 Runtime.getRuntime().exec(read()); // SINK
 }
 HttpServletRequest cached;
 String read() { return cached.getParameter("v"); }
}
