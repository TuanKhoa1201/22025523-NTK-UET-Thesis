package counterexamples;

import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class CE08_MultiHopIndirectHelperChain {
    public void handleTwoHopTainted(HttpServletRequest request, Statement stmt) throws Exception {
        String raw = request.getParameter("filter");
        String routed = stepOne(raw);
        stmt.executeQuery("SELECT * FROM logs WHERE msg='" + routed + "'");
    }

    public void handleDeepUnboundedChain(HttpServletRequest request, Statement stmt) throws Exception {
        String raw = request.getParameter("filter");
        String deep = hop1(raw);
        stmt.executeQuery("SELECT * FROM logs WHERE msg='" + deep + "'");
    }

    private String stepOne(String a) {
        return stepTwo(a);
    }

    private String stepTwo(String b) {
        return b;
    }

    private String hop1(String v) {
        return hop2(v);
    }

    private String hop2(String v) {
        return hop3(v);
    }

    private String hop3(String v) {
        return hop4(v);
    }

    private String hop4(String v) {
        return "unreachable_within_3_hop_budget";
    }
}
