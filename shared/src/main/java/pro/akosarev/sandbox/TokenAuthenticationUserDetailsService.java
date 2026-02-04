package pro.akosarev.sandbox;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.time.Instant;

/**
 * Практическое значение:
 * Этот класс становится поставщиком данных пользователя для Spring Security.
 * Когда система получает токен аутентификации, она вызывает метод loadUserDetails(), который:
 *   Проверяет тип токена (RefreshToken, AccessToken или TokenUser)
 *   Загружает информацию о пользователе
 *   Проверяет, не деактивирован ли токен в БД
 *   Возвращает объект UserDetails с правами доступа
 * Это контракт - Spring Security знает, что может вызвать этот метод для получения данных пользователя по токену.
 **/
public class TokenAuthenticationUserDetailsService
        implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private final JdbcTemplate jdbcTemplate;

    public TokenAuthenticationUserDetailsService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken authenticationToken)
            throws UsernameNotFoundException {
        // Обработка RefreshToken
        if (authenticationToken.getPrincipal() instanceof RefreshToken refreshToken) {
            return new TokenUser(refreshToken.subject(), "nopassword", true, true,
                    !this.jdbcTemplate.queryForObject("""
                            select exists(select id from t_deactivated_token where id = ?)
                            """, Boolean.class, refreshToken.id()) &&
                    refreshToken.expiresAt().isAfter(Instant.now()),
                    true,
                    null, // RefreshToken не содержит authorities
                    refreshToken);
        }

        // Обработка AccessToken
        if (authenticationToken.getPrincipal() instanceof AccessToken accessToken) {
            return new TokenUser(accessToken.subject(), "nopassword", true, true,
                    !this.jdbcTemplate.queryForObject("""
                            select exists(select id from t_deactivated_token where id = ?)
                            """, Boolean.class, accessToken.id()) &&
                    accessToken.expiresAt().isAfter(Instant.now()),
                    true,
                    accessToken.authorities().stream()
                            .map(SimpleGrantedAuthority::new)
                            .toList(),
                    null); // AccessToken не нуждается в RefreshToken
        }

        // Обработка уже построенного TokenUser (из JwtAuthenticationConverter)
        if (authenticationToken.getPrincipal() instanceof TokenUser tokenUser) {
            return tokenUser;
        }

        throw new UsernameNotFoundException("Principal must be of type RefreshToken or AccessToken");
    }
}