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
 */
@RestController
@RequestMapping("/api/greetings")
public class GreetingsRestController {

    /**
     * Возвращает приветствие для аутентифицированного пользователя.
     *
     * @param user данные аутентифицированного пользователя
     * @return объект с текстом приветствия
     */
    @GetMapping
    public ResponseEntity<Greeting> getGreeting(@AuthenticationPrincipal UserDetails user) {
        // Responds with JSON greeting for authenticated user
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(new Greeting("Hello, %s!".formatted(user.getUsername())));
    }

    /**
     * Модель приветствия.
     *
     * @param greeting текст приветствия
     */
    public record Greeting(String greeting) {
    }
}
