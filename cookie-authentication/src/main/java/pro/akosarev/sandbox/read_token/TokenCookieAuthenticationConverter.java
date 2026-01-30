package pro.akosarev.sandbox.read_token;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import pro.akosarev.sandbox.Token;

import java.util.function.Function;
import java.util.stream.Stream;

/**
 * Конвертер для извлечения аутентификации из куки запроса.
 * Ищет куку с именем {@code __Host-auth-token} и преобразует её значение в объект {@link PreAuthenticatedAuthenticationToken}.
 */
public class TokenCookieAuthenticationConverter implements AuthenticationConverter {

    private final Function<String, Token> tokenCookieStringDeserializer;

    /**
     * Конструктор конвертера.
     *
     * @param tokenCookieStringDeserializer десериализатор строки токена в объект Token
     */
    public TokenCookieAuthenticationConverter(Function<String, Token> tokenCookieStringDeserializer) {
        this.tokenCookieStringDeserializer = tokenCookieStringDeserializer;
    }

    /**
     * Преобразует HTTP-запрос в объект аутентификации на основе куки с именем __Host-auth-token
     *
     * @param request HTTP-запрос
     * @return объект аутентификации или null, если кука не найдена
     */
    @Override
    public Authentication convert(HttpServletRequest request) {
        if (request.getCookies() != null) {
            // Filters cookies to find authentication token
            return Stream.of(request.getCookies())
                    .filter(cookie -> cookie.getName().equals("__Host-auth-token"))
                    .findFirst()
                    .map(cookie -> {
                        var token = tokenCookieStringDeserializer.apply(cookie.getValue());
//  пояснение в bearer аутентификации
                        return new PreAuthenticatedAuthenticationToken(token, cookie.getValue());
                    })
                    .orElse(null);
        }

        return null;
    }
}
