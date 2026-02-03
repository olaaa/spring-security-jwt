package pro.akosarev.sandbox;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class TokenUser extends User {

    private final RefreshToken refreshToken;

    public TokenUser(String username, String password, Collection<? extends GrantedAuthority> authorities, 
                     RefreshToken refreshToken) {
        super(username, password, authorities);
        this.refreshToken = refreshToken;
    }

    public TokenUser(String username, String password, boolean enabled, boolean accountNonExpired, 
                     boolean credentialsNonExpired, boolean accountNonLocked, 
                     Collection<? extends GrantedAuthority> authorities, RefreshToken refreshToken) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        this.refreshToken = refreshToken;
    }

    public RefreshToken getRefreshToken() {
        return refreshToken;
    }
}
