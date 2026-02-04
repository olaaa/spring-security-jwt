package pro.akosarev.sandbox;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import java.util.function.Function;

// AbstractHttpConfigurer используется для создания кастомных конфигураторов безопасности в Spring Security.
public class JwtAuthenticationConfigurer extends AbstractHttpConfigurer<JwtAuthenticationConfigurer, HttpSecurity> {

    private Function<AccessToken, String> accessTokenStringSerializer;

    private Function<RefreshToken, String> refreshTokenStringSerializer;

    private Function<String, AccessToken> accessTokenStringDeserializer;

    private Function<String, RefreshToken> refreshTokenStringDeserializer;

    private JdbcTemplate jdbcTemplate;

    @Autowired
    UserDetailsService userDetailsService;

//    добавляем адрес в исключение при обработке Csrf-фильтром
    /**
     * CSRF — защита для сценария с сессионной cookie, которую браузер добавляет сам.
     * Тогда вредоносная страница может отправить POST, и cookie уйдёт автоматически.
     * Поэтому сервер требует CSRF‑токен.
     * В вашем случае авторизация идет через Authorization: Basic ... (для выдачи токенов)
     * или Authorization: Bearer ... (для остальных запросов).
     * Браузер сам этот заголовок не добавляет, его ставит только ваш клиент. Значит CSRF‑атака не сработает:
     * без заголовка запрос не будет аутентифицирован.
     */
    @Override
    public void init(HttpSecurity builder) {
        var csrfConfigurer = builder.getConfigurer(CsrfConfigurer.class);
        if (csrfConfigurer != null) {
            csrfConfigurer.ignoringRequestMatchers(PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/jwt/tokens"));
        }
    }

    /**
     * Configures authentication pipeline with JWT and refresh tokens
     */
    @Override
    public void configure(HttpSecurity builder) {
        var requestJwtTokensFilter = new RequestJwtTokensFilter();
        requestJwtTokensFilter.setAccessTokenStringSerializer(this.accessTokenStringSerializer);
        requestJwtTokensFilter.setRefreshTokenStringSerializer(this.refreshTokenStringSerializer);

        // создаем новый фильтр
        var jwtAuthenticationFilter = new AuthenticationFilter(builder.getSharedObject(AuthenticationManager.class),
                new JwtAuthenticationConverter(jdbcTemplate, this.accessTokenStringDeserializer, this.refreshTokenStringDeserializer));
        jwtAuthenticationFilter
//        При успехе: пропускает CSRF-проверку для данного запроса, так как куки при аутентификации не используются
//        Поведение по умолчнию было бы отправить на index.html
                .setSuccessHandler((request, response, authentication)
                        -> CsrfFilter.skipRequest(request));
//        по умолчанию редиректил бы на форму логина
        jwtAuthenticationFilter
                .setFailureHandler((request, response, exception)
                        -> response.sendError(HttpServletResponse.SC_FORBIDDEN)); // 403

        var authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        var authenticationUserDetailsService = new TokenAuthenticationUserDetailsService(this.jdbcTemplate);
        authenticationProvider.setPreAuthenticatedUserDetailsService(
                authenticationUserDetailsService);


        var refreshTokenFilter = new RefreshTokenFilter(userDetailsService);
        refreshTokenFilter.setAccessTokenStringSerializer(this.accessTokenStringSerializer);

        var jwtLogoutFilter = new JwtLogoutFilter(this.jdbcTemplate);

        builder.addFilterAfter(requestJwtTokensFilter, BasicAuthenticationFilter.class)
//                обязательно до CsrfFilter
                .addFilterBefore(jwtAuthenticationFilter, CsrfFilter.class)
                .addFilterAfter(refreshTokenFilter, ExceptionTranslationFilter.class)
                .addFilterAfter(jwtLogoutFilter, ExceptionTranslationFilter.class)
                .authenticationProvider(authenticationProvider);
    }

    public JwtAuthenticationConfigurer refreshTokenStringSerializer(
            Function<RefreshToken, String> refreshTokenStringSerializer) {
        this.refreshTokenStringSerializer = refreshTokenStringSerializer;
        return this;
    }

    public JwtAuthenticationConfigurer accessTokenStringSerializer(
            Function<AccessToken, String> accessTokenStringSerializer) {
        this.accessTokenStringSerializer = accessTokenStringSerializer;
        return this;
    }

    public JwtAuthenticationConfigurer accessTokenStringDeserializer(
            Function<String, AccessToken> accessTokenStringDeserializer) {
        this.accessTokenStringDeserializer = accessTokenStringDeserializer;
        return this;
    }

    public JwtAuthenticationConfigurer refreshTokenStringDeserializer(
            Function<String, RefreshToken> refreshTokenStringDeserializer) {
        this.refreshTokenStringDeserializer = refreshTokenStringDeserializer;
        return this;
    }

    public JwtAuthenticationConfigurer jdbcTemplate(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        return this;
    }
}