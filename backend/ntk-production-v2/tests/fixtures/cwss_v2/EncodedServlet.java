// SYNTHETIC security regression fixture; never execute repository code.
import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.nio.file.*;
class EncodedServlet extends HttpServlet {
 Connection conn;
 protected void doPost(HttpServletRequest request, HttpServletResponse response) throws javax.servlet.ServletException, IOException {
 String value = request.getParameter("value");
 response.setContentType("text/html");
 PrintWriter out = response.getWriter();
 out.println(org.owasp.encoder.Encode.forHtml(value)); // SINK
 }
}
