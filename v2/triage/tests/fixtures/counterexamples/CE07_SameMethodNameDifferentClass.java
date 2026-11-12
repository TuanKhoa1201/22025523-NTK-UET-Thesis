package counterexamples;

import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class CE07_SameMethodNameDifferentClass {
    public void handleExternal(HttpServletRequest request, Statement stmt) throws Exception {
        String param = request.getParameter("q");
        String bar = ExternalUnprovidedHelper.doSomething(param);
        stmt.executeQuery("SELECT * FROM items WHERE tag='" + bar + "'");
    }

    public void handleInnerDispatch(HttpServletRequest request, Statement stmt) throws Exception {
        String param = request.getParameter("q");
        String bar = new UnsafeHelper().doSomething(param);
        stmt.executeQuery("SELECT * FROM items WHERE tag='" + bar + "'");
    }

    private static class UnusedSafeHelper {
        public static String doSomething(String x) {
            return "constant_safe";
        }
    }

    private class UnsafeHelper {
        public String doSomething(String x) {
            return x;
        }
    }
}
