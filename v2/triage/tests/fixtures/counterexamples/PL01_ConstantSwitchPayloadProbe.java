import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class PL01_ConstantSwitchPayloadProbe {
    public void handle(HttpServletRequest request, Connection conn) throws Exception {
        String param = request.getParameter("q");
        String bar = "";
        String guess = "ABC";
        char switchTarget = guess.charAt(1);
        switch (switchTarget) {
            case 'A':
                bar = param;
                break;
            case 'B':
                bar = "constant";
                break;
            default:
                bar = param;
                break;
        }
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM t WHERE c = '" + bar + "'");
    }
}
