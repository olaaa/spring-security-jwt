package pro.akosarev.sandbox;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.csrf.CsrfFilter;
import pro.akosarev.sandbox.create_token.TokenCookieAuthenticationConverter;

import java.util.Date;
import java.util.function.Function;

/**
 * Конфигуратор для настройки аутентификации на основе кук с токенами.
 *
 * <p>Этот класс объединяет разрозненные компоненты в единый механизм:</p>
 * <ul>
 *     <li>Настраивает логаут: при выходе удаляется кука и ID токена заносится в "черный список" в БД.</li>
 *     <li>Добавляет фильтр, который проверяет наличие куки в каждом входящем запросе.</li>
 *     <li>Регистрирует провайдер, который проверяет расшифрованный токен на валидность и актуальность.</li>
 * </ul>
 */
public class TokenCookieAuthenticationConfigurer
        extends AbstractHttpConfigurer<TokenCookieAuthenticationConfigurer, HttpSecurity> {

    private Function<String, Token> tokenCookieStringDeserializer;

    private JdbcTemplate jdbcTemplate;

    /**
     * Инициализирует конфигурацию, настраивая механизм логаута.
     * Добавляет обработчики для удаления куки и занесения идентификатора токена в список деактивированных.
     *
     * @param builder объект настройки HTTP-безопасности
     */
    @Override
    public void init(HttpSecurity builder) {
        builder.logout(logout -> logout.addLogoutHandler(
                        new CookieClearingLogoutHandler("__Host-auth-token"))

                .addLogoutHandler((request, response, authentication) -> {
                    if (authentication != null &&
                        authentication.getPrincipal() instanceof TokenUser user) {
                        this.jdbcTemplate.update("INSERT INTO t_deactivated_token (id, c_keep_until) VALUES (?, ?)",
                                user.getToken().id(), Date.from(user.getToken().expiresAt()));

                        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                    }
                }));
    }

    /**
     * Конфигурирует фильтр аутентификации и провайдер.
     * Добавляет {@link AuthenticationFilter} после {@link CsrfFilter}.
     *
     * @param builder объект настройки HTTP-безопасности
     */
    @Override
    public void configure(HttpSecurity builder) {
        var cookieAuthenticationFilter = new AuthenticationFilter(
                builder.getSharedObject(AuthenticationManager.class),
                new TokenCookieAuthenticationConverter(this.tokenCookieStringDeserializer));
        cookieAuthenticationFilter.setSuccessHandler((request, response, authentication) -> {
        });
        cookieAuthenticationFilter.setFailureHandler(
                new AuthenticationEntryPointFailureHandler(
                        new Http403ForbiddenEntryPoint()
                )
        );

        var authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(
                new TokenAuthenticationUserDetailsService(this.jdbcTemplate));

        builder.addFilterAfter(cookieAuthenticationFilter, CsrfFilter.class)
                .authenticationProvider(authenticationProvider);
    }

    /**
     * Устанавливает десериализатор токена из строки.
     *
     * @param tokenCookieStringDeserializer функция десериализации
     * @return текущий объект конфигуратора
     */
    public TokenCookieAuthenticationConfigurer tokenCookieStringDeserializer(
            Function<String, Token> tokenCookieStringDeserializer) {
        this.tokenCookieStringDeserializer = tokenCookieStringDeserializer;
        return this;
    }

    /**
     * Устанавливает шаблон для работы с БД.
     *
     * @param jdbcTemplate шаблон для работы с БД
     * @return текущий объект конфигуратора
     */
    public TokenCookieAuthenticationConfigurer jdbcTemplate(
            JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        return this;
    }
}
