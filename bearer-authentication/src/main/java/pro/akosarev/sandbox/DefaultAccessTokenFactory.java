package pro.akosarev.sandbox;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

/**
 * Стандартная фабрика для создания Access Token
 * Access Token создается на основе Authentication и содержит полный набор authorities
 */
public class DefaultAccessTokenFactory implements Function<Authentication, AccessToken> {

    private Duration tokenTtl = Duration.ofMinutes(5);

    @Override
    public AccessToken apply(Authentication authentication) {
        var now = Instant.now();
        var authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        
        return new AccessToken(
                UUID.randomUUID(),
                authentication.getName(),
                authorities,
                now,
                now.plus(this.tokenTtl)
        );
    }

    public void setTokenTtl(Duration tokenTtl) {
        this.tokenTtl = tokenTtl;
    }
}
