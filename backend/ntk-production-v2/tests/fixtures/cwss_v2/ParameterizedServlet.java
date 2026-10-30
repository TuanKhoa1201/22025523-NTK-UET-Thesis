// SYNTHETIC security regression fixture; never execute repository code.
import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.nio.file.*;
class ParameterizedServlet extends HttpServlet {
 protected void doPost(HttpServletRequest request, HttpServletResponse response) throws javax.servlet.ServletException, IOException {
 String value = request.getParameter("value");
 try (Connection conn = DriverManager.getConnection(System.getProperty("ntk.fixture.jdbcUrl"));
 PreparedStatement statement = conn.prepareStatement("SELECT name FROM accounts WHERE id = ?")) {
 statement.setString(1, value);
 statement.executeQuery(); // SINK
 } catch (SQLException error) {throw new javax.servlet.ServletException(error);}
 }
}
