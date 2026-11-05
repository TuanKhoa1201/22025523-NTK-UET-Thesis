// SYNTHETIC CWSS fixture. Not a deployed application or benchmark label.
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;
@RestController
public class PathController {
 @GetMapping("/example")
 public void run(HttpServletRequest request) throws Exception {
  String input = request.getParameter("value");
  java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(input)); // SINK
 }
}
