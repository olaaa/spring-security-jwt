package pro.akosarev.sandbox;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

/**
 * Фильтр для предоставления CSRF-токена клиенту в виде JSON.
 * Обновлён для Spring Security 7.0 с улучшенной обработкой CSRF токенов
 */
public class GetCsrfTokenFilter extends OncePerRequestFilter {

    private CsrfTokenRepository csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public GetCsrfTokenFilter() {
        // Конструктор по умолчанию
    }

    public void setCsrfTokenRepository(CsrfTokenRepository csrfTokenRepository) {
        this.csrfTokenRepository = csrfTokenRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Простая проверка пути для /csrf endpoint
        if (request.getMethod().equals("GET") && request.getRequestURI().equals("/csrf")) {
            // Получаем CSRF токен из репозитория
            var deferredToken = this.csrfTokenRepository.loadDeferredToken(request, response);
            var csrfToken = deferredToken.get();

            if (csrfToken != null) {
                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);

                // Записываем токен в формате JSON
                this.objectMapper.writeValue(response.getWriter(), csrfToken);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
