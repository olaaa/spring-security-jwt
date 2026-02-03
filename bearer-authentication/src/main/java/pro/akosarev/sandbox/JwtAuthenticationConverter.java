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
import java.util.function.Function;
import java.util.stream.Collectors;

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
            var token = authorization.replace("Bearer ", "");

            // Пытаемся десериализовать как Access Token
            var accessToken = this.accessTokenStringDeserializer.apply(token);
            // Authenticates access token if valid and not deactivated
            if (accessToken != null && accessToken.expiresAt().isAfter(Instant.now()) &&
                this.jdbcTemplate.queryForList("SELECT id FROM t_deactivated_token WHERE id = ?",
                        accessToken.id()).isEmpty()) {
                return new PreAuthenticatedAuthenticationToken(
                        new TokenUser(accessToken.subject(), "{noop}", true, true, true, true,
                                accessToken.authorities().stream()
                                        .map(SimpleGrantedAuthority::new)
                                        .collect(Collectors.toUnmodifiableList()),
                                null),
                        token,
                        accessToken.authorities().stream()
                                .map(SimpleGrantedAuthority::new)
                                .toList());
            }

            // Пытаемся десериализовать как Refresh Token
            var refreshToken = this.refreshTokenStringDeserializer.apply(token);
            if (refreshToken != null && refreshToken.expiresAt().isAfter(Instant.now())) {
                boolean isTokenValid = this.jdbcTemplate.queryForList("SELECT id FROM t_deactivated_token WHERE id = ?",
                                refreshToken.id())
                        .isEmpty();
                if (isTokenValid) {
                    var refreshAuthorities = List.<SimpleGrantedAuthority>of();
                    return new PreAuthenticatedAuthenticationToken(
                            new TokenUser(refreshToken.subject(), "{noop}", true, true, true, true,
                                    refreshAuthorities, refreshToken),
                            token,
                            null);
                }
            }
        }

        return null;
    }

    public void setAccessTokenStringDeserializer(Function<String, AccessToken> accessTokenStringDeserializer) {
        this.accessTokenStringDeserializer = accessTokenStringDeserializer;
    }

    public void setRefreshTokenStringDeserializer(Function<String, RefreshToken> refreshTokenStringDeserializer) {
        this.refreshTokenStringDeserializer = refreshTokenStringDeserializer;
    }
}