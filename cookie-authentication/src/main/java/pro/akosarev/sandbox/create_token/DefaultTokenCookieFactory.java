package pro.akosarev.sandbox.create_token;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import pro.akosarev.sandbox.Token;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

/**
 * Реализация фабрики токенов по умолчанию.
 * Создает объект {@link Token} на основе данных аутентифицированного пользователя.
 */
public class DefaultTokenCookieFactory implements Function<Authentication, Token> {

    private Duration tokenTtl = Duration.ofDays(1);

    /**
     * Создает токен на основе объекта аутентификации.
     *
     * @param authentication объект аутентификации пользователя
     * @return созданный токен
     */
    @Override
    public Token apply(Authentication authentication) {
        var now = Instant.now();
        // Creates token with authorities and expiration time
        return new Token(UUID.randomUUID(),
                authentication.getName(),
                authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList(),
                now,
                now.plus(this.tokenTtl));
    }

    /**
     * Устанавливает время жизни токена.
     *
     * @param tokenTtl время жизни токена
     */
    public void setTokenTtl(Duration tokenTtl) {
        this.tokenTtl = tokenTtl;
    }
}
