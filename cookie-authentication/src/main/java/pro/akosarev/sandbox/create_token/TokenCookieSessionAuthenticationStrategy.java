package pro.akosarev.sandbox.create_token;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.function.Function;

import pro.akosarev.sandbox.Token;

/**
 * Устанавливаем аутентификационную куку при успешной аутентификации. Вместо сессии -- дефолтной стратегии.
 * Стратегия аутентификации сессий на основе кук с токенами.
 * Обновлена для Spring Security 7.0 с улучшенной безопасностью кук
 */
public class TokenCookieSessionAuthenticationStrategy implements SessionAuthenticationStrategy {

    private Function<Authentication, Token> tokenCookieFactory = new DefaultTokenCookieFactory();

//    сериализуем
    private Function<Token, String> tokenStringSerializer;

    /*
    * этот метод выполнится в случае успешной аутентификации
    * */
    @Override
    public void onAuthentication( Authentication authentication,
                                 HttpServletRequest request,
                                 HttpServletResponse response) throws SessionAuthenticationException {
        
        if (authentication instanceof UsernamePasswordAuthenticationToken) { // чтобы не создавался каждый раз токен на успешную куки-аутентификацию
            var token = this.tokenCookieFactory.apply(authentication);
            var tokenString = this.tokenStringSerializer.apply(token);

            // Создаём защищённую куку с улучшенными параметрами безопасности
// хеадер set-cookie
            var cookie = new Cookie("__Host-auth-token", tokenString);
            cookie.setPath("/");
//           этого требует префикс __Host-
            cookie.setDomain(null);
            cookie.setSecure(true); // только по https
//            только сервер имел доступ к этой куке
            cookie.setHttpOnly(true);
            cookie.setMaxAge((int) ChronoUnit.SECONDS.between(Instant.now(), token.expiresAt()));
            
            // Добавляем SameSite атрибут для защиты от CSRF
            cookie.setAttribute("SameSite", "Strict");

            response.addCookie(cookie);
        }
    }

    public void setTokenCookieFactory(Function<Authentication, Token> tokenCookieFactory) {
        this.tokenCookieFactory = tokenCookieFactory;
    }

    public void setTokenStringSerializer(Function<Token, String> tokenStringSerializer) {
        this.tokenStringSerializer = tokenStringSerializer;
    }
}
