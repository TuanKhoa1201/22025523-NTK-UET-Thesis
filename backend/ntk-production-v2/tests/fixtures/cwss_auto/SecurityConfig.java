// SYNTHETIC estimate of source configuration, not runtime authentication proof.
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
@Configuration
@EnableWebSecurity
public class SecurityConfig {
 @Bean
 SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
  return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll()).build();
 }
}
