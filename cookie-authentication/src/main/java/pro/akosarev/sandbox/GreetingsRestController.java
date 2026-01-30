package pro.akosarev.sandbox;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST-контроллер для получения приветствий.
 * Использует современные практики Spring Security 7.0
 */
@RestController
@RequestMapping("/api/greetings")
public class GreetingsRestController {

    /**
     * Возвращает приветствие для аутентифицированного пользователя.
     * Использует @AuthenticationPrincipal для получения данных пользователя
     */
    @GetMapping
    public ResponseEntity<Greeting> getGreeting(@AuthenticationPrincipal UserDetails user) {
        // Проверяем наличие аутентификации
        if (user == null) {
            return ResponseEntity.status(401).build();
        }
        
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(new Greeting("Hello, %s!".formatted(user.getUsername())));
    }

    /**
     * Модель приветствия с использованием Java Records
     */
    public record Greeting(String greeting) {
    }
}
