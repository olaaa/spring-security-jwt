
package pro.akosarev.sandbox;

import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import pro.akosarev.sandbox.create_token.TokenCookieJweStringSerializer;
import pro.akosarev.sandbox.create_token.TokenCookieSessionAuthenticationStrategy;
import pro.akosarev.sandbox.read_token.TokenCookieJweStringDeserializer;

/**
 * Основной класс приложения для демонстрации аутентификации через куки в SPA.
 * Обновлено для Spring Boot 4.0 и Spring Security 7.0
 */
@SpringBootApplication
public class SpaCookieAuthenticationApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpaCookieAuthenticationApplication.class, args);
    }

//    то же самое, что было в рефреш токен
    @Bean
    public TokenCookieJweStringSerializer tokenCookieJweStringSerializer(
            @Value("${jwt.cookie-token-key}") String cookieTokenKey
    ) throws Exception {
        return new TokenCookieJweStringSerializer(new DirectEncrypter(
                OctetSequenceKey.parse(cookieTokenKey)
        ));
    }

//    перегруженное создание бина. Это все можно сделать через спринг аутовайред
    @Bean
    public TokenCookieAuthenticationConfigurer tokenCookieAuthenticationConfigurer(
            @Value("${jwt.cookie-token-key}") String cookieTokenKey,
            JdbcTemplate jdbcTemplate
    ) throws Exception {
        return new TokenCookieAuthenticationConfigurer()
                .tokenCookieStringDeserializer(new TokenCookieJweStringDeserializer(
                        new DirectDecrypter(
                                OctetSequenceKey.parse(cookieTokenKey)
                        )
                ))
                .jdbcTemplate(jdbcTemplate);
    }

    /**
     * Настраивает цепочку фильтров безопасности Spring Security 7.
     * Использует Lambda DSL и простые строковые паттерны вместо MvcRequestMatcher
     */
    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            TokenCookieAuthenticationConfigurer tokenCookieAuthenticationConfigurer,
            TokenCookieJweStringSerializer tokenCookieJweStringSerializer) throws Exception {

        var tokenCookieSessionAuthenticationStrategy = new TokenCookieSessionAuthenticationStrategy();
        tokenCookieSessionAuthenticationStrategy.setTokenStringSerializer(tokenCookieJweStringSerializer);

        return http
                // пояснение в ридми файле
                .httpBasic(Customizer.withDefaults())
//                не работает логаут из index! НО работает из manager
                .formLogin(Customizer.withDefaults())

                // Добавляем фильтр для CSRF
                .addFilterAfter(new GetCsrfTokenFilter(),
                        org.springframework.security.web.access.ExceptionTranslationFilter.class)

                // Авторизация с Lambda DSL - используем простые строковые паттерны
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/manager.html").hasRole("MANAGER")
                        .requestMatchers("/manager").hasRole("MANAGER")
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/index.html").permitAll()
                        .requestMatchers("/").permitAll()
                        .anyRequest().authenticated()
                )

                // Управление сессиями с Lambda DSL
                .sessionManagement(session -> session
//                        отключаем сессии
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//  устанавливаем нашу стратегию
                        .sessionAuthenticationStrategy(tokenCookieSessionAuthenticationStrategy)
                )

                // CSRF конфигурация с Lambda DSL
                .csrf(csrf -> csrf
//  spring security по умолчанию использует http сессии, поэтому нужно поменять на CookieCsrfTokenRepository
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
// handler, который не обфусцирует csrf-токен. По умолчанию используется XorCsrfTokenRequestAttributeHandler
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
// для того, чтобы цсрф-токен не обновлялся каждый раз, когда проходим аутентификацию
                        .sessionAuthenticationStrategy((authentication, request, response) -> {
                        })
                )

                // Применяем кастомный конфигуратор
                .with(tokenCookieAuthenticationConfigurer, Customizer.withDefaults())
                .build();
    }

    /**
     * Configures user lookup via JDBC template
     */
    @Bean
    public UserDetailsService userDetailsService(JdbcTemplate jdbcTemplate) {
        return username -> jdbcTemplate.query(
                        "SELECT * FROM t_user WHERE c_username = ?",
                        getUserDetailsRowMapper(jdbcTemplate),
                        username
                )
                .stream()
                .findFirst()
                .orElse(null);
    }

    private static @NonNull RowMapper<UserDetails> getUserDetailsRowMapper(JdbcTemplate jdbcTemplate) {
        return (rs, i) -> {
            int userId = rs.getInt("id");
            String username = rs.getString("c_username");
            String password = rs.getString("c_password");

            var authorities = jdbcTemplate.query(
                    "SELECT c_authority FROM t_user_authority WHERE id_user = ?",
                    (rs1, i1) -> new SimpleGrantedAuthority(rs1.getString("c_authority")),
                    userId
            );

            return User.builder()
                    .username(username)
                    .password(password)
                    .authorities(authorities)
                    .build();
        };
    }
}