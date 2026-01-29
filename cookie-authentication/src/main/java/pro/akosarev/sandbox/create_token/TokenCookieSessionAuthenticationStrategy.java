package pro.akosarev.sandbox.create_token;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import pro.akosarev.sandbox.Token;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.function.Function;

/**
 * Стратегия аутентификации сессии через куки с токенами.
 *
 * <p>Эта стратегия срабатывает один раз — сразу после того, как пользователь успешно ввел логин и пароль.
 * Вместо создания обычной серверной сессии (JSESSIONID), она генерирует защищенный токен,
 * превращает его в зашифрованную JWE-строку и устанавливает эту строку в куку браузера.</p>
 *
 * <p>Параметры куки настроены максимально строго (HttpOnly, Secure, __Host-), чтобы защитить
 * пользователя от кражи его данных через скрипты или незащищенные каналы связи.</p>
 */
public class TokenCookieSessionAuthenticationStrategy implements SessionAuthenticationStrategy {

    private Function<Authentication, Token> tokenCookieFactory = new DefaultTokenCookieFactory();

    private Function<Token, String> tokenStringSerializer = Objects::toString;

    /**
     * Выполняется при успешной аутентификации.
     * Создает токен, сериализует его и добавляет в куку {@code __Host-auth-token}.
     *
     * @param authentication объект аутентификации
     * @param request        HTTP-запрос
     * @param response       HTTP-ответ
     * @throws SessionAuthenticationException в случае ошибки аутентификации сессии
     */
    @Override
    public void onAuthentication(@NonNull Authentication authentication, @NonNull HttpServletRequest request,
                                 @NonNull HttpServletResponse response) throws SessionAuthenticationException {
        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            var token = this.tokenCookieFactory.apply(authentication);
            var tokenString = this.tokenStringSerializer.apply(token);

            var cookie = new Cookie("__Host-auth-token", tokenString);
            cookie.setPath("/");
            cookie.setDomain(null);
            cookie.setSecure(true);
            cookie.setHttpOnly(true);
            cookie.setMaxAge((int) ChronoUnit.SECONDS.between(Instant.now(), token.expiresAt()));

            response.addCookie(cookie);
        }
    }

    /**
     * Устанавливает фабрику для создания токенов.
     *
     * @param tokenCookieFactory фабрика токенов
     */
    public void setTokenCookieFactory(Function<Authentication, Token> tokenCookieFactory) {
        this.tokenCookieFactory = tokenCookieFactory;
    }

    /**
     * Устанавливает сериализатор токена в строку.
     *
     * @param tokenStringSerializer сериализатор токена
     */
    public void setTokenStringSerializer(Function<Token, String> tokenStringSerializer) {
        this.tokenStringSerializer = tokenStringSerializer;
    }
}
