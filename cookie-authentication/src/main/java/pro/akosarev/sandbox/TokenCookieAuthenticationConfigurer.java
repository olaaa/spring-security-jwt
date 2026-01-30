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
import pro.akosarev.sandbox.read_token.TokenCookieAuthenticationConverter;

import java.util.Date;
import java.util.function.Function;

/**
 * Конфигуратор для настройки аутентификации на основе кук с токенами.
 *
 * Аналогично модулю bearer-authentication
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
        // Configures logout; clears cookie; persists token for deactivation
        builder.logout(logout -> logout
                .addLogoutHandler(
                        new CookieClearingLogoutHandler("__Host-auth-token"))
// блокируем id токена. Скопировано из логаут фильтра модуля bearer-authentication
                .addLogoutHandler((request, response, authentication) -> {
                    if (authentication != null &&
                        authentication.getPrincipal() instanceof TokenUser user) {
                        // Persists token expiration for deactivation purposes
                        jdbcTemplate.update("INSERT INTO t_deactivated_token (id, c_keep_until) VALUES (?, ?)",
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
        // Создаём фильтр аутентификации. Это фильтр Spring Security, который:
        // 1) вызывает AuthenticationConverter, чтобы получить Authentication из запроса,
        // 2) передаёт этот Authentication в AuthenticationManager,
        // 3) в зависимости от результата вызывает success/failure handler.
        var cookieAuthenticationFilter = new AuthenticationFilter(
                // Берём AuthenticationManager из shared-объектов HttpSecurity.
                // Это «движок» Spring Security, который прогоняет Authentication через подходящие AuthenticationProvider'ы.
                builder.getSharedObject(AuthenticationManager.class),

                // Наша реализация интерфейса org.springframework.security.web.authentication.AuthenticationConverter
                new TokenCookieAuthenticationConverter(tokenCookieStringDeserializer)
        );

        // Задаём обработчик успешной аутентификации.
        // Здесь он пустой: т.е. при успехе не пишем ничего в response и просто продолжаем цепочку фильтров.
        cookieAuthenticationFilter.setSuccessHandler((request, response, authentication) -> {
        });

        // Задаём обработчик неуспешной аутентификации (например, токен отсутствует/битый/просрочен/невалиден).
        // AuthenticationEntryPointFailureHandler оборачивает EntryPoint и запускает его при ошибке.
        cookieAuthenticationFilter.setFailureHandler(
                new AuthenticationEntryPointFailureHandler(
                        // Http403ForbiddenEntryPoint отвечает клиенту статусом 403 Forbidden.
                        new Http403ForbiddenEntryPoint()
                )
        );

        // Создаём провайдер аутентификации для сценария "pre-auth".
        // PreAuthenticatedAuthenticationProvider предназначен для случаев, когда «учётные данные»
        // уже получены извне (например, из заголовка/сертификата/cookie), а провайдеру остаётся
        // только загрузить пользователя и подтвердить его.
        var authenticationProvider = new PreAuthenticatedAuthenticationProvider();

        // Подключаем сервис, который по pre-auth токену возвращает UserDetails (пользователя и его authorities).
        // Внутри обычно: проверка токена, проверка "не отозван ли", загрузка прав и т.п.
        authenticationProvider.setPreAuthenticatedUserDetailsService(
//  класс   из shared модуля
                new TokenAuthenticationUserDetailsService(jdbcTemplate)
        );

        // Регистрируем фильтр в цепочке фильтров Spring Security:
        // addFilterAfter(..., CsrfFilter.class) означает "вставить cookieAuthenticationFilter сразу после CsrfFilter".
        // Далее в этой же DSL-цепочке регистрируем созданный AuthenticationProvider.
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
