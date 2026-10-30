// SYNTHETIC: JDBC URL/driver are deployment prerequisites, never executed here.
import javax.servlet.http.*;
import javax.servlet.ServletException;
import java.sql.*;
import java.io.*;
public class SqlServlet extends HttpServlet {
 protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
  String value = request.getParameter("value");
  try (Connection conn = DriverManager.getConnection(System.getProperty("ntk.fixture.jdbcUrl"));
       Statement statement = conn.createStatement()) {
   statement.executeUpdate(value); // SINK
  } catch (SQLException error) { throw new ServletException(error); }
 }
}
