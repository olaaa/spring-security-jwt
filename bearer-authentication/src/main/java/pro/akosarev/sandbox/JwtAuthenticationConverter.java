package pro.akosarev.sandbox;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Spring Security по умолчанию не знает, как обрабатывать JWT-токены из заголовка Authorization: Bearer.
 *  Автор создает собственный конвертер, который:
 *  Извлекает токены из HTTP-заголовков
 *  Десериализует их в AccessToken или RefreshToken
 *  Проверяет валидность в базе данных
 *  Создает правильный объект Authentication
 */
public class JwtAuthenticationConverter implements AuthenticationConverter {

    private final JdbcTemplate jdbcTemplate;

    private Function<String, AccessToken> accessTokenStringDeserializer;

    private Function<String, RefreshToken> refreshTokenStringDeserializer;

    public JwtAuthenticationConverter(JdbcTemplate jdbcTemplate, Function<String, AccessToken> accessTokenStringDeserializer, Function<String, RefreshToken> refreshTokenStringDeserializer) {
        this.jdbcTemplate = jdbcTemplate;
        this.accessTokenStringDeserializer = accessTokenStringDeserializer;
        this.refreshTokenStringDeserializer = refreshTokenStringDeserializer;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        var authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith("Bearer ")) {
            var token = extractBearerToken(authorization);

            // Пытаемся десериализовать как Access Token
            var accessToken = this.accessTokenStringDeserializer.apply(token);
            if (isValidAccessToken(accessToken)) {
                return createAccessTokenAuthentication(accessToken, token);
            }

            // Пытаемся десериализовать как Refresh Token
            var refreshToken = this.refreshTokenStringDeserializer.apply(token);
            if (isValidRefreshToken(refreshToken)) {
                return createRefreshTokenAuthentication(refreshToken, token);
            }
        }

        return null;
    }

    private String extractBearerToken(String authorization) {
        return authorization.replace("Bearer ", "");
    }

    private boolean isTokenNotDeactivated(UUID tokenId) {
        return this.jdbcTemplate.queryForList("SELECT id FROM t_deactivated_token WHERE id = ?", tokenId)
                .isEmpty();
    }

    private List<SimpleGrantedAuthority> convertToGrantedAuthorities(List<String> authorities) {
        return authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    private boolean isValidAccessToken(AccessToken accessToken) {
        return accessToken != null &&
               accessToken.expiresAt().isAfter(Instant.now()) &&
               isTokenNotDeactivated(accessToken.id());
    }

    private boolean isValidRefreshToken(RefreshToken refreshToken) {
        return refreshToken != null &&
               refreshToken.expiresAt().isAfter(Instant.now()) &&
               isTokenNotDeactivated(refreshToken.id());
    }

    private PreAuthenticatedAuthenticationToken createAccessTokenAuthentication(AccessToken accessToken, String token) {
        var authorities = convertToGrantedAuthorities(accessToken.authorities());
        return new PreAuthenticatedAuthenticationToken(
                new TokenUser(accessToken.subject(), "{noop}", true, true, true, true, authorities, null),
                token,
                accessToken.authorities().stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList());
    }

    private PreAuthenticatedAuthenticationToken createRefreshTokenAuthentication(RefreshToken refreshToken, String token) {
        var refreshAuthorities = List.<SimpleGrantedAuthority>of();
        return new PreAuthenticatedAuthenticationToken(
                new TokenUser(refreshToken.subject(), "{noop}", true, true, true, true, refreshAuthorities, refreshToken),
                token,
                null);
    }

    public void setAccessTokenStringDeserializer(Function<String, AccessToken> accessTokenStringDeserializer) {
        this.accessTokenStringDeserializer = accessTokenStringDeserializer;
    }

    public void setRefreshTokenStringDeserializer(Function<String, RefreshToken> refreshTokenStringDeserializer) {
        this.refreshTokenStringDeserializer = refreshTokenStringDeserializer;
    }
}