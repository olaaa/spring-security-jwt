package pro.akosarev.sandbox;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Date;

public class JwtLogoutFilter extends OncePerRequestFilter {

    private RequestMatcher requestMatcher = PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/jwt/logout");

    private final JdbcTemplate jdbcTemplate;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (this.requestMatcher.matches(request)) {
            TokenUser authenticatedUser = extractAuthenticatedTokenUser();

            if (authenticatedUser != null) {
                deactivateRefreshToken(authenticatedUser);
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                return;
            }

            throw new AccessDeniedException("User must be authenticated with JWT");
        }
        filterChain.doFilter(request, response);
    }

    private TokenUser extractAuthenticatedTokenUser() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        if (securityContext == null) {
            return null;
        }

        Authentication authentication = securityContext.getAuthentication();
        if (!(authentication instanceof PreAuthenticatedAuthenticationToken)) {
            return null;
        }

        Object principal = authentication.getPrincipal();
        return principal instanceof TokenUser ? (TokenUser) principal : null;
    }

    private void deactivateRefreshToken(TokenUser user) {
        RefreshToken refreshToken = user.getRefreshToken();
        this.jdbcTemplate.update(
                "insert into t_deactivated_token (id, c_keep_until) values (?, ?)",
                refreshToken.id(),
                Date.from(refreshToken.expiresAt())
        );
    }
    public JwtLogoutFilter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void setRequestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }
}