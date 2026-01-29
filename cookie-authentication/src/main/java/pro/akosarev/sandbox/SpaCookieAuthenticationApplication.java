package pro.akosarev.sandbox;

import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import pro.akosarev.sandbox.create_token.TokenCookieJweStringSerializer;
import pro.akosarev.sandbox.create_token.TokenCookieSessionAuthenticationStrategy;
import pro.akosarev.sandbox.read_token.TokenCookieJweStringDeserializer;

/**
 * Основной класс приложения для демонстрации аутентификации через куки в SPA.
 *
 * <p>Этот класс настраивает механизмы безопасности, позволяющие отказаться от серверных сессий
 * в пользу зашифрованных токенов (JWE), которые хранятся прямо в браузере пользователя в защищенных куках.
 * Это делает приложение "stateless" (без состояния на сервере), что упрощает его масштабирование.</p>
 */
@SpringBootApplication
public class SpaCookieAuthenticationApplication {

    /**
     * Точка входа в приложение.
     *
     * @param args аргументы командной строки
     */
    public static void main(String[] args) {
        SpringApplication.run(SpaCookieAuthenticationApplication.class, args);
    }

    /**
     * Создает бин сериализатора токена в строку JWE.
     *
     * @param cookieTokenKey ключ для шифрования токена
     * @return настроенный экземпляр TokenCookieJweStringSerializer
     * @throws Exception если ключ шифрования некорректен
     */
    @Bean
    public TokenCookieJweStringSerializer tokenCookieJweStringSerializer(
            @Value("${jwt.cookie-token-key}") String cookieTokenKey
    ) throws Exception {
        return new TokenCookieJweStringSerializer(new DirectEncrypter(
                OctetSequenceKey.parse(cookieTokenKey)
        ));
    }

    /**
     * Создает бин конфигуратора аутентификации через куки.
     *
     * @param cookieTokenKey ключ для дешифрования токена
     * @param jdbcTemplate   шаблон для работы с БД (для проверки деактивированных токенов)
     * @return настроенный экземпляр TokenCookieAuthenticationConfigurer
     * @throws Exception если ключ дешифрования некорректен
     */
    @Bean
    public TokenCookieAuthenticationConfigurer tokenCookieAuthenticationConfigurer(
            @Value("${jwt.cookie-token-key}") String cookieTokenKey,
            JdbcTemplate jdbcTemplate
    ) throws Exception {
        // Configures deserializer and database access for token authentication
        return new TokenCookieAuthenticationConfigurer()
                .tokenCookieStringDeserializer(new TokenCookieJweStringDeserializer(
                        new DirectDecrypter(
                                OctetSequenceKey.parse(cookieTokenKey)
                        )
                ))
                .jdbcTemplate(jdbcTemplate);
    }

    /**
     * Настраивает цепочку фильтров безопасности Spring Security.
     *
     * <p>Здесь происходит основная магия:</p>
     * <ul>
     *     <li>Включается стандартный вход через форму и Basic Auth для первичной проверки пользователя.</li>
     *     <li>Настраивается <b>Stateless</b> политика сессий — сервер не будет создавать JSESSIONID.</li>
     *     <li>Устанавливается кастомная стратегия {@code tokenCookieSessionAuthenticationStrategy}, которая
     *     после успешного входа создаст и отдаст пользователю куку с зашифрованным токеном.</li>
     *     <li>Настраивается защита от CSRF с использованием кук, доступных для чтения фронтендом.</li>
     * </ul>
     *
     * @param http                                    объект для настройки HTTP-безопасности
     * @param tokenCookieAuthenticationConfigurer     конфигуратор аутентификации через куки
     * @param tokenCookieJweStringSerializer          сериализатор токена для стратегии аутентификации
     * @return настроенная цепочка фильтров
     */
    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            TokenCookieAuthenticationConfigurer tokenCookieAuthenticationConfigurer,
            TokenCookieJweStringSerializer tokenCookieJweStringSerializer) {
        var tokenCookieSessionAuthenticationStrategy = new TokenCookieSessionAuthenticationStrategy();
        tokenCookieSessionAuthenticationStrategy.setTokenStringSerializer(tokenCookieJweStringSerializer);

        // Configures basic and form login; adds CSRF filter
        http.httpBasic(Customizer.withDefaults())
                .formLogin(Customizer.withDefaults())
                .addFilterAfter(new GetCsrfTokenFilter(), ExceptionTranslationFilter.class)
                .authorizeHttpRequests(authorizeHttpRequests ->
                        // Authorizes manager and default routes; requires authentication otherwise
                        authorizeHttpRequests
                                .requestMatchers("/manager.html", "/manager").hasRole("MANAGER")
                                .requestMatchers("/error", "index.html").permitAll()
                                .anyRequest().authenticated())
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        .sessionAuthenticationStrategy(tokenCookieSessionAuthenticationStrategy))
                .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                        .sessionAuthenticationStrategy((authentication, request, response) -> {}));

        http.with(tokenCookieAuthenticationConfigurer, Customizer.withDefaults());

        return http.build();
    }

    /**
     * Создает реализацию UserDetailsService для загрузки данных пользователя из БД.
     *
     * @param jdbcTemplate шаблон для работы с БД
     * @return сервис загрузки данных пользователя
     */
    @Bean
    public UserDetailsService userDetailsService(JdbcTemplate jdbcTemplate) {
        return username -> jdbcTemplate.query("select * from t_user where c_username = ?",
                // Builds user details from database records
                (rs, i) -> User.builder()
                        .username(rs.getString("c_username"))
                        .password(rs.getString("c_password"))
                        .authorities(
                                jdbcTemplate.query("select c_authority from t_user_authority where id_user = ?",
                                        (rs1, i1) ->
                                                new SimpleGrantedAuthority(rs1.getString("c_authority")),
                                        rs.getInt("id")))
                        .build(), username).stream().findFirst().orElse(null);
    }
}
