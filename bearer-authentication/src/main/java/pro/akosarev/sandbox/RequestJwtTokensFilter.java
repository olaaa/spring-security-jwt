package pro.akosarev.sandbox;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.function.Function;

/**
 * Зачем нужен эндпоинт /jwt/tokens
 * Это эндпоинт для первичного получения JWT токенов — точка входа в систему JWT-аутентификации.
 * Да, это стандартное решение в современных API.
 *
 * Проблема, которую он решает
 * JWT токены не хранятся на сервере (stateless подход). Но их нужно как-то выдать пользователю в первый раз.
 * Для этого и нужен отдельный эндпоинт.
 *
 * OncePerRequestFilter — это абстрактный класс из Spring Security, который обеспечивает выполнение фильтра строго один раз на каждый HTTP-запрос.
 * Ключевые преимущества:
 * ✅ Предотвращение дублирования — защита от повторного выполнения при forward/include запросах
 */
public class RequestJwtTokensFilter extends OncePerRequestFilter {

    private RequestMatcher requestMatcher = PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/jwt/tokens");

    private Function<Authentication, RefreshToken> refreshTokenFactory = new DefaultRefreshTokenFactory();

    private Function<Authentication, AccessToken> accessTokenFactory = new DefaultAccessTokenFactory();

    private Function<RefreshToken, String> refreshTokenStringSerializer = Object::toString;

    private Function<AccessToken, String> accessTokenStringSerializer = Object::toString;

    private ObjectMapper objectMapper = new ObjectMapper();


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (this.requestMatcher.matches(request)) {
            // ✅ ДОБАВЛЕНО - правильный способ получения контекста
            var context = SecurityContextHolder.getContext();
            Authentication authentication = context.getAuthentication();
            // Проверяем, что пользователь аутентифицирован через Basic Auth (не через JWT)
                if (context != null &&
                    authentication.isAuthenticated() &&
                    !(context.getAuthentication() instanceof PreAuthenticatedAuthenticationToken)) {
                    // Стандартный подход: оба токена создаются из Authentication
                    var refreshToken = this.refreshTokenFactory.apply(context.getAuthentication());
                    var accessToken = this.accessTokenFactory.apply(context.getAuthentication());

                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    this.objectMapper.writeValue(response.getWriter(),
                            new Tokens(this.accessTokenStringSerializer.apply(accessToken),
                                    accessToken.expiresAt().toString(),
                                    this.refreshTokenStringSerializer.apply(refreshToken),
                                    refreshToken.expiresAt().toString()));
                    return;
                }

            throw new AccessDeniedException("User must be authenticated");
        }

        filterChain.doFilter(request, response);
    }

    public void setRequestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }


    public void setRefreshTokenFactory(Function<Authentication, RefreshToken> refreshTokenFactory) {
        this.refreshTokenFactory = refreshTokenFactory;
    }

    public void setAccessTokenFactory(Function<Authentication, AccessToken> accessTokenFactory) {
        this.accessTokenFactory = accessTokenFactory;
    }

    public void setRefreshTokenStringSerializer(Function<RefreshToken, String> refreshTokenStringSerializer) {
        this.refreshTokenStringSerializer = refreshTokenStringSerializer;
    }

    public void setAccessTokenStringSerializer(Function<AccessToken, String> accessTokenStringSerializer) {
        this.accessTokenStringSerializer = accessTokenStringSerializer;
    }

    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }
}