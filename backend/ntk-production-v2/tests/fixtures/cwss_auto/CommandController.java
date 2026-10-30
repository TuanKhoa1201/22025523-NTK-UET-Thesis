// SYNTHETIC CWSS fixture. Not a deployed application or benchmark label.
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;
@RestController
public class CommandController {
 @GetMapping("/example")
 public void run(HttpServletRequest request) throws Exception {
  String input = request.getParameter("value");
  Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", input}); // SINK
 }
}
