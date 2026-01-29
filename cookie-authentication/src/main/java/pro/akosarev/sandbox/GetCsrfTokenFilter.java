package pro.akosarev.sandbox;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import java.io.IOException;

/**
 * Фильтр для предоставления CSRF-токена клиенту.
 *
 * <p>В современных Single Page Applications (SPA) для защиты от CSRF-атак сервер требует, чтобы
 * каждый "опасный" запрос (POST, PUT, DELETE) содержал специальный секретный токен в заголовке.
 * Этот фильтр создает эндпоинт (по умолчанию GET /csrf), через который фронтенд-приложение
 * может в любой момент получить актуальный CSRF-токен в формате JSON.</p>
 */
public class GetCsrfTokenFilter extends OncePerRequestFilter {

    private final RequestMatcher requestMatcher = PathPatternRequestMatcher.pathPattern(HttpMethod.GET, "/csrf");

    private CsrfTokenRepository csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Устанавливает репозиторий CSRF-токенов.
     *
     * @param csrfTokenRepository репозиторий токенов
     */
    public void setCsrfTokenRepository(CsrfTokenRepository csrfTokenRepository) {
        this.csrfTokenRepository = csrfTokenRepository;
    }

    /**
     * Выполняет фильтрацию запроса. Если запрос соответствует сопоставителю, возвращает CSRF-токен.
     *
     * @param request     HTTP-запрос
     * @param response    HTTP-ответ
     * @param filterChain цепочка фильтров
     * @throws ServletException в случае ошибки сервлета
     * @throws IOException      в случае ошибки ввода-вывода
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Responds with CSRF token for matching requests
        if (this.requestMatcher.matches(request)) {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            this.objectMapper.writeValue(response.getWriter(), this.csrfTokenRepository.loadDeferredToken(request, response).get());
            return;
        }

        filterChain.doFilter(request, response);
    }
}
