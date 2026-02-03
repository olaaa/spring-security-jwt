package pro.akosarev.sandbox;

import org.springframework.security.core.Authentication;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

/**
 * Стандартная фабрика для создания Refresh Token
 * Refresh Token содержит только subject - минимальную информацию
 */
public class DefaultRefreshTokenFactory implements Function<Authentication, RefreshToken> {

    private Duration tokenTtl = Duration.ofDays(1);

    @Override
    public RefreshToken apply(Authentication authentication) {
        var now = Instant.now();
        return new RefreshToken(
                UUID.randomUUID(), 
                authentication.getName(), 
                now, 
                now.plus(this.tokenTtl)
        );
    }

    public void setTokenTtl(Duration tokenTtl) {
        this.tokenTtl = tokenTtl;
    }
}
